@load base/frameworks/notice/main.zeek
@load base/protocols/conn/main.zeek

# Measures time between SYN and SYN-ACK per stream
module NetworkRTT;

export {
  # Paramerters and alert thresholds
  const synack_timeout: interval = 1sec;     # max allowed SYN->SYN-ACK gap
  const per_pair_window: count   = 5;        # rolling window per IP pair
  const global_window: count     = 10;       # rolling window globally

  const single_rtt_threshold: double    = 0.300;  # seconds per stream
  const pair_stddev_threshold: double   = 0.100;  # seconds per IP pair
  const global_stddev_threshold: double = 0.200;  # seconds per connections globally

  # Distinguishes SYN-ACK source/destination direction when set to false
  const canonicalize_pairs: bool = T;

  const debug_print: bool = F;

  redef enum Notice::Type += {
    High_RTT,
    High_RTT_Jitter_PerPair,
    High_RTT_Jitter_Global
  };
}

redef LogAscii::use_json = T;

function variance(v: vector of double): double
  {
  local n: count = |v|;
  if ( n < 2 ) return 0.0;
  local sum: double = 0.0;
  local i: count = 0;
  while ( i < n ) { sum += v[i]; i += 1; }
  local mu: double = sum / (n + 0.0);
  local vs: double = 0.0;
  i = 0;
  while ( i < n ) { local d = v[i] - mu; vs += d*d; i += 1; }
  return vs / (n + 0.0);
  }

function stddev(v: vector of double): double
  { return sqrt(variance(v)); }

function v_push_trim(v: vector of double, x: double, maxlen: count)
  {
  v[|v|] = x;
  if ( |v| > maxlen )
    {
    local out: vector of double;
    local i: count = 1;
    while ( i < |v| ) { out[|out|] = v[i]; i += 1; }
    v = out;
    }
  }

function key_for_pair(a: addr, b: addr): string
  {
  if ( canonicalize_pairs )
    {
    local x = a; local y = b;
    if ( x > y ) { local t=x; x=y; y=t; }
    return fmt("%s|%s", x, y);
    }
  return fmt("%s|%s", a, b);
  }

# ---------------- per-connection state ----------------
type SynState: record {
  syn_ts: time &optional;        # time of client SYN
  synack_ts: time &optional;     # time of server SYN-ACK
  done: bool &default=F;         # whether RTT was logged per connection
};

# State keyed by Zeek's per-connection UID
global syn_state: table[string] of SynState;

# Rolling windows
global pair_rtts:   table[string] of vector of double;  # seconds per IP pair
global global_rtts: vector of double;

# ---------------- logs ----------------
redef enum Log::ID += { LOG_RTT_STREAM, LOG_RTT_PAIR, LOG_RTT_GLOBAL };

type StreamRTTLog: record {
  ts: time &log;
  uid: string &log;
  orig_h: addr &log;
  orig_p: port &log;
  resp_h: addr &log;
  resp_p: port &log;
  rtt_ms: double &log;
};

type PairRTTLog: record {
  ts: time &log;
  orig_h: addr &log;
  resp_h: addr &log;
  rtt_ms: double &log;        # current sample (ms)
  n_pair: count &log;
  pair_stddev_s: double &log; # stddev (seconds)
};

type GlobalRTTLog: record {
  ts: time &log;
  rtt_ms: double &log;          # current sample (ms)
  n_global: count &log;
  global_stddev_s: double &log; # stddev (seconds)
};

event zeek_init()
  {
  Log::create_stream(LOG_RTT_STREAM, [$columns=StreamRTTLog, $path="rtt_stream"]);
  Log::create_stream(LOG_RTT_PAIR,   [$columns=PairRTTLog,   $path="rtt_pair"]);
  Log::create_stream(LOG_RTT_GLOBAL, [$columns=GlobalRTTLog, $path="rtt_global"]);
  }

# ---------------- built-in connection lifecycle ----------------

# Called when Zeek first recognizes a new 5-tuple flow.
event new_connection(c: connection)
  {
  # Initialize state record for this UID
  syn_state[c$uid] = [$done=F];
  }

# Called when an initial connection attempt is detected (SYN seen).
event connection_attempt(c: connection)
  {
  if ( c$uid in syn_state )
    {
    local st = syn_state[c$uid];
    if ( ! st?$syn_ts )
      {
      st$syn_ts = network_time();
      syn_state[c$uid] = st;
      }
    }
  else
    syn_state[c$uid] = [$syn_ts=network_time(), $done=F];
  }

# Called when TCP handshake completes (3-way done; connection is established).
# Corresponds to the last ACK
event connection_established(c: connection)
  {
  # Nothing to do here except ensure state exists.
  if ( !(c$uid in syn_state) )
    syn_state[c$uid] = [$done=F];
  }

# Removes reset connections and timeouts
event connection_state_remove(c: connection)
  {
  if ( c$uid in syn_state )
    delete syn_state[c$uid];
  }

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string)
  {
  # Ensure state exists
  if ( !(c$uid in syn_state) )
    syn_state[c$uid] = [$done=F];

  local st = syn_state[c$uid];
  local now = network_time();

  # First SYN from origin (no ACK bit): set/refresh syn_ts (handles retransmissions)
  if ( is_orig && /S/ in flags && ! (/A/ in flags) )
    {
    st$syn_ts = now;
    syn_state[c$uid] = st;
    return;
    }

  # Computes RTT after SYN-ACK
  if ( ! is_orig && /S/ in flags && /A/ in flags && st?$syn_ts && ! st$done )
    {
    local gap: interval = now - st$syn_ts;

    # Drop obviously stale pairings
    if ( gap > synack_timeout )
      {
      delete syn_state[c$uid];
      return;
      }

    local rtt_s: double = gap / 1sec;
    local rtt_ms: double = rtt_s * 1000.0;

    # 1) Stream-level log (full 4-tuple)
    Log::write(LOG_RTT_STREAM, [$ts=now, $uid=c$uid,
                                $orig_h=c$id$orig_h, $orig_p=c$id$orig_p,
                                $resp_h=c$id$resp_h, $resp_p=c$id$resp_p,
                                $rtt_ms=rtt_ms]);

    # 2) Pair-level rolling stats (IP pair, direction optional)
    local pk = key_for_pair(c$id$orig_h, c$id$resp_h);
    if ( pk !in pair_rtts ) pair_rtts[pk] = vector();
    v_push_trim(pair_rtts[pk], rtt_s, per_pair_window);
    local pr   = pair_rtts[pk];
    local pcnt = |pr|;
    local psd  = stddev(pr);

    Log::write(LOG_RTT_PAIR, [$ts=now, $orig_h=c$id$orig_h, $resp_h=c$id$resp_h,
                              $rtt_ms=rtt_ms, $n_pair=pcnt, $pair_stddev_s=psd]);

    # 3) Global rolling stats
    v_push_trim(global_rtts, rtt_s, global_window);
    local gcnt = |global_rtts|;
    local gsd  = stddev(global_rtts);

    Log::write(LOG_RTT_GLOBAL, [$ts=now, $rtt_ms=rtt_ms,
                                $n_global=gcnt, $global_stddev_s=gsd]);

    if ( debug_print )
      print fmt("RTT %.3f ms uid=%s %s:%s -> %s:%s (SYN->SYN-ACK)",
                rtt_ms, c$uid, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);

    # Alerts
    if ( rtt_s > single_rtt_threshold )
      NOTICE([$note=High_RTT,
              $msg=fmt("High RTT %.3f s %s:%s -> %s:%s",
                       rtt_s, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
              $conn=c]);

    if ( pcnt >= 5 && psd > pair_stddev_threshold )
      NOTICE([$note=High_RTT_Jitter_PerPair,
              $msg=fmt("RTT jitter high %s -> %s: stddev=%.3f s (n=%d)",
                       c$id$orig_h, c$id$resp_h, psd, pcnt),
              $conn=c]);

    if ( gcnt >= 5 && gsd > global_stddev_threshold )
      NOTICE([$note=High_RTT_Jitter_Global,
              $msg=fmt("GLOBAL RTT jitter high: stddev=%.3f s (n=%d)",
                       gsd, gcnt)]);

    # mark complete for steam UID to only log the first handshake RTT
    st$synack_ts = now;
    st$done = T;
    syn_state[c$uid] = st;
    }
  }
