@load base/frameworks/notice/main.zeek
@load base/frameworks/logging/main.zeek
@load base/protocols/http/main.zeek

module AppLatency;

export {
  redef enum Notice::Type += {
    High_HTTP_Response_Latency,
    High_HTTP_Response_Variance_For_Session,
    High_Global_HTTP_Response_Variance
  };

  const latency_threshold: interval = 0.25sec;    # single response delay alert

  # Alerts based on standard deviation in seconds
  const app_flow_stddev_threshold: double = 0.5;    # per-connection stddev (sec)
  const global_stddev_threshold: double   = 0.75;    # global stddev (sec)
  const global_window_size = 10;                    # rolling window size
}

# --- tiny vector helpers (no base/utils/vector needed) ---
function v_push(v: vector of interval, x: interval) { v[|v|] = x; }

function v_trim_front(v: vector of interval, n: count)
  {
  if ( n == 0 ) return;
  if ( n >= |v| ) { v = vector(); return; }
  local out: vector of interval;
  local i: count = n;
  while ( i < |v| ) { out[|out|] = v[i]; i += 1; }
  v = out;
  }
# ----------------------------------------------------------
# Custom log record & stream
  type AJLog: record {
    ts: time &log;
    proto: string &log;
    uid: string &log &optional;
    id: conn_id &log &optional;
    orig_h: addr &log &optional;
    resp_h: addr &log &optional;
    gap_s: double &log &optional;
    stddev_s: double &log &optional;
    note: string &log &optional;  # "High latency for single request" | "High variance in latency for session" | "High variance globally"
  };
redef enum Log::ID += { LOG_ApplicationLatency };

event zeek_init()
  {
  Log::create_stream(LOG_ApplicationLatency, [$columns=AJLog, $path="application_latency"]);
  }

global last_request_time: table[conn_id] of time;
global app_flow_deltas: table[conn_id] of vector of interval;
global global_deltas: vector of interval;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
  {
  last_request_time[c$id] = network_time();
  }

event http_reply(c: connection, version: string, code: count, reason: string)
  {
  if ( c$id !in last_request_time )
    return;

  local now   = network_time();
  local delta = now - last_request_time[c$id];    # interval
  last_request_time[c$id] = now;

  # 1) High latency response to request
  if ( delta > latency_threshold )
    {
    # ADDED: Print statement for console output
    print fmt("ALERT: High latency %s -> %s: %.2f sec", c$id$orig_h, c$id$resp_h, (delta / 1.0sec));
    NOTICE([$note=High_HTTP_Response_Latency,
            $msg=fmt("High latency %s -> %s: %.2f sec",
                     c$id$orig_h, c$id$resp_h, (delta / 1.0sec)),
            $conn=c]);
    Log::write(LOG_ApplicationLatency,
                 [$ts=now, $proto="HTTP", $orig_h=c$id$orig_h, $resp_h=c$id$resp_h, $gap_s=(delta / 1.0sec), $note="High_HTTP_Response_Latency"]);
    }

  # 2) Stddev Per-connection 
  if ( c$id !in app_flow_deltas )
    app_flow_deltas[c$id] = vector();

  v_push(app_flow_deltas[c$id], delta);

  if ( |app_flow_deltas[c$id]| >= 5 )
    {
    local n: count = |app_flow_deltas[c$id]|;
    local sum: double = 0.0;

    # mean (seconds)
    local i: count = 0;
    while ( i < n )
      {
      sum += (app_flow_deltas[c$id][i] / 1.0sec);
      i += 1;
      }
    local mean_s: double = sum / (n + 0.0);

    # variance (seconds^2)
    local var_sum: double = 0.0;
    i = 0;
    while ( i < n )
      {
      local d_s: double = (app_flow_deltas[c$id][i] / 1.0sec);
      var_sum += (d_s - mean_s) * (d_s - mean_s);
      i += 1;
      }
    local var_s2: double = var_sum / (n + 0.0);
    local stddev_s: double = sqrt(var_s2);

    if ( stddev_s > app_flow_stddev_threshold )
      {
      local alert_2_time = network_time();
      print fmt("ALERT: High latency stddev %s -> %s: %.2f sec over %d samples", c$id$orig_h, c$id$resp_h, stddev_s, n);
      NOTICE([$note=High_HTTP_Response_Variance_For_Session,
              $msg=fmt("High latency stddev %s -> %s: %.2f sec over %d samples",
                       c$id$orig_h, c$id$resp_h, stddev_s, n),
              $conn=c]);
      Log::write(LOG_ApplicationLatency,
                 [$ts=alert_2_time, $proto="HTTP", $orig_h=c$id$orig_h, $resp_h=c$id$resp_h, $stddev_s=stddev_s, $note="High_HTTP_Response_Variance_For_Session"]);
      app_flow_deltas[c$id] = vector();  # reset after alert
      }
    }

  # 3) Global application latency stddev
  v_push(global_deltas, delta);
  if ( |global_deltas| > global_window_size )
    v_trim_front(global_deltas, |global_deltas| - global_window_size);

  if ( |global_deltas| == global_window_size )
    {
    local g_n: count = |global_deltas|;
    local g_sum: double = 0.0;
    
    local g_i: count = 0;
    while ( g_i < g_n )
      {
      g_sum += (global_deltas[g_i] / 1.0sec);
      g_i += 1;
      }
    local g_mean: double = g_sum / (g_n + 0.0);

    local g_var_sum: double = 0.0;
    g_i = 0;
    while ( g_i < g_n )
      {
      local g_d_s: double = (global_deltas[g_i] / 1.0sec);
      g_var_sum += (g_d_s - g_mean) * (g_d_s - g_mean);
      g_i += 1;
      }
    local g_var: double = g_var_sum / (g_n + 0.0);
    local g_stddev: double = sqrt(g_var);

    if ( g_stddev > global_stddev_threshold )
      {
      local alert_3_time = network_time();
      print fmt("ALERT: High variance in application latency: %.2f sec over last %d responses", g_stddev, g_n);
      NOTICE([$note=High_Global_HTTP_Response_Variance,
              $msg=fmt("High variance in application latency: %.2f sec over last %d responses",
                       g_stddev, g_n)]);
            Log::write(LOG_ApplicationLatency,
                 [$ts=alert_3_time, $proto="HTTP", $stddev_s=g_stddev, $note="High_Global_HTTP_Response_Variance"]);
      global_deltas = vector();  # clear after alert
      }
    }
  }

event connection_state_remove(c: connection)
  {
  delete last_request_time[c$id];
  delete app_flow_deltas[c$id];
  }
