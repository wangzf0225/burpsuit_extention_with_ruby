require 'webrick'
require 'json'
require 'cgi'
require 'net/http'
require 'openssl'

# PATH          = File.dirname($LOAD_PATH[0])+"/"

load "#{PATH}src/lib.class.rb"

# OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE

# makelog(String[] string)each[:name]
def makelog(string)
  time = Time.new().to_s
  file = File.open("#{$path}logs",'a')
  file.puts time+"\t"+string
  file.close
end




#Run this function to send an HTTP request to webserver and receive response and return response's body
#
hash  = {
    :method     => "POST",
    :url        => "https://www.baidu.com/?s=123",
    :use_ssl    => true,
    :headers    => {
                "host" => "www.baidu.com",
                "user-agent" => " BiBi/1.0 (iPhone; iOS 9.2; Scale/2.00)",
                "connection" => "keep-alive"
    },
    :body  => 's=123',
}

def send_http_request(hash)

  uri = URI.parse(hash[:url])
  # http_init = Net::HTTP.new(uri.host, uri.port, "127.0.0.1", "8009")
  http_init = Net::HTTP.new(uri.host, uri.port)
  http_init.read_timeout = 500
  http_init.use_ssl = hash[:use_ssl]
  http_init.verify_mode = OpenSSL::SSL::VERIFY_NONE
  # http_init.ca_file = '/etc/openssl/cacert.pem'
  if uri.query
    http_path = "#{uri.path}?#{uri.query}"
  else
    http_path = uri.path
  end

  hash[:headers]["host"] = uri.host
  hash[:headers].delete("accept-encoding") if hash[:headers].keys.include?("accept-encoding")
  if hash[:method].downcase == 'get'
    req = Net::HTTP::Get.new(http_path, hash[:headers])
  elsif hash[:method].downcase == 'post'
    req = Net::HTTP::Post.new(http_path,hash[:headers])
  else
    makelog "HTTP method is undefined."
    return {:state => false, :data => nil, :message => "HTTP method is undefined."}
  end
  req.body = hash[:post_body]
  #If request success once,return,or retry request 3 times.
  status_error_code = 0
  3.times() {
    #|time| puts "time #{time}"
    resp = http_init.request(req)
    status_error_code = resp.code
    unless resp.nil?
      makelog("Send request successfully. URL:#{hash[:url]} .")
      ret = resp
      # p ret.body
      return {:state => true, :data => ret, :message => "Success."}
    end

  }
      # makelog("Occur an error when requesting URL. URL:#{hash[:url]}\tCode:#{resp.code}\tMessage:#{resp.message}.Retring...")
  return {:state => false, :data => nil, :message => "Send HTTP request failed with status code #{status_error_code}."}
end


# Hash parse_request(String request)
def parse_request(request)
  if request.nil? or request.empty?
    filename = '/tmp/request'
  else
    time  = Time.new()
    filename = "/tmp/request_#{time.strftime('%Y%m%d')}#{rand(0xffff)}"
    file = File.new(filename,'w')
    file.puts request
    file.close
  end
  req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
  ret = Hash.new
  File.open(filename) do |socket|
    req.parse(socket).class

    get_query_para = {}
    unless req.query_string.nil?
    req.query_string.split("&").each{|each|
      name,value = each.split("=")[0],each.split("=")[1]
      get_query_para.store(name,value)
    }
    end

    post_query_para = {}
    if req.request_method == "POST" and not req.body.empty?
      if req.query.empty?
        req.body.split("&").each{|each|
          name,value = each.split("=")[0],each.split("=")[1]
          post_query_para.store(name,value)
        }
      else
        post_query_para = req.query
      end
    end


    cookies  = {}
    unless req.cookies.nil?
    req.cookies.each{|each|
      name,value = each.name,each.value
      cookies.store(name,value)
    }
    end

    header = {}
    req.header.each{|k,v|      header.store(k,v.join())    }


    ret.store(:host,            req.host)
    ret.store(:query,           get_query_para)
    ret.store(:header,          header)
    ret.store(:para,            post_query_para)
    ret.store(:request_line,    req.request_line)
    ret.store(:method,          req.request_method)
    ret.store(:unparsed_uri,    req.unparsed_uri)
    ret.store(:uri,             req.path)
    ret.store(:raw_header,      req.raw_header)
    ret.store(:body,            req.body)
    ret.store(:cookies,         cookies)
    ret.store(:cookiesObject,   req.cookies)

  end

  unless request.nil? or request.empty?
    File.delete(filename)
  end

  ret

end

# Array
def conduct_policy(formatedRequest)

  load "#{PATH}src/policyCandidate.rb"

  rules = DATA
  audit_items = []
  rules.each{|each|
    # Initailize Stat Machine class
    selector = StateMachine.new(formatedRequest,each)

    # If null
    next if each[:action] == NULL

    # If include in keys
    if each[:action] == INCLUDE_IN_KEYS
      info = selector.includeInKeys
      unless info.empty?
        audit_items << {:name => each[:method],:data => info}
      end
    end

    # If include in values
    if each[:action] == INCLUDE_IN_VALUES
      info = selector.includeInValues
      unless info.empty?
        audit_items << {:name => each[:method],:data => info}
      end
    end

    # if
    if each[:action] == MATCH_KEY_WORDS_IN_VALUE
      info = selector.matchKeyWordsInValue
      unless info.empty?
        audit_items << {:name => each[:method],:data => info}
      end
    end


    # if
    if each[:action] == MATCH_KEY_WORDS_IN_NAME
      info = selector.matchKeyWordsInName
      unless info.empty?
        audit_items << {:name => each[:method],:data => info}
      end
    end

    # ADD CODE HERE
    # >>>>>>>>>>>>>
    #
    # if each[:action] == CONSTANT
    #   info = selector.methodname
    #   unless info.empty?
    #     audit_items << {:name => each[:method],:data => info}
    #   end
    # end
  }
  audit_items
end


def lunchRequestBasedAudit(checklist,formatedRequest)

  makelog "Execute function lunchRequestAudit"
  resultlist = []
  checklist.each{|each|

    makelog "Go to execute method lunchRequestBasedAudit::#{each[:name]} with checklist \'#{each}\'"

    controller = RequestBasedAnalyze.new(formatedRequest)
    res = controller.send each[:name],each[:data]
    resultlist << res
    # break
  }
  resultlist
end

def dataEdit(checkResult)
  display = ""
  checkResult.each{|each|
    if each[:state]
      display += "\nVulnerability Item:#{each[:name]}\n"
      display += "Mark:#{each[:echo]}\n"
      display += "Attck Vector:#{each[:vector]}\n"
      display += "----------------------------------------------------------------\n"
    end
  }
  display
end
# puts JSON.pretty_generate conduct_policy(formatedRequest)

def test()
  resultlist = []
  formatedRequest = parse_request("")
  checklist = conduct_policy(formatedRequest)
  resultlist += lunchRequestBasedAudit(checklist,formatedRequest)
  # basic = BasicAnalyzer.new(formatedRequest)
  # resultlist << basic.paraSetEmpty
  # ret = basic.paraSetEmpty
  puts dataEdit(resultlist)
end

# test()