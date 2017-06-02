
class StateMachine


  def initialize(formatedRequest,rule)
    @formatedRequest  = formatedRequest
    @rule    = rule
  end

  def includeInKeys()
    scope   = @rule[:scope]
    conllection = []
    scope.each{|each|
      intersection = (@formatedRequest[each].keys & @rule[:condition])
      next if intersection.size == 0

      intersection.each{|one|
        item = {}
        item.store(:scope,  each)
        item.store(:name,   one)
        item.store(:value,  @formatedRequest[each][one])
        conllection << item
      }
    }
    conllection
  end

  def includeInValues()
    def find_key(hash,value)
      hash.each{|k,v| return k if v = value }
    end
    scope   = @rule[:scope]
    conllection = []
    scope.each{|each|
      intersection = (@formatedRequest[each].values & @rule[:condition])
      intersection.each{|one|
        item = {}
        item.store(:scope,  each)
        item.store(:name,   find_key(@formatedRequest[each],each))
        item.store(:value,  one)
        conllection << item
      }
    }
    conllection
  end

  def matchKeyWordsInValue()
    scope  = @rule[:scope]
    conllection = []
    scope.each{|each|
      # @rule[:condition][0]
      if @formatedRequest[each] =~ /@rule[condintion][0]/
        item = {}
        item.store(:scope,  each)
        item.store(:name,   each)
        item.store(:value,  @formatedRequest[each])
        conllection << item
      end
    }
    conllection
  end

  # MATCH_KEY_WORDS_IN_NAME
  def matchKeyWordsInName()
    scope  = @rule[:scope]
    conllection = []
    scope.each{|each|
      @formatedRequest[each].each{|name, value|
        if name =~ @rule[:condition][0]
          item = {}
          item.store(:scope,  each)
          item.store(:name,   name)
          item.store(:value,  value)
          conllection << item
        end
      }
    }
    conllection
  end

end

class RequestBasedAnalyze


  def initialize(formatedRequest)
    checklist = @checklist
    @formatedRequest = formatedRequest
  end

  def joinPara(hash,jointer,separator)
    catch = []
    hash.each{|key,value|    catch << "#{key}#{jointer}#{value}"}
    catch.join(separator)
  end

  def redirectParameterCheck(data)

    data.each{|each|
      k_v = @formatedRequest[each[:scope]]
      k_v.each{|k,v|   k_v[k] = CGI.escape 'http://www.abc.com\.test.com/' if k.downcase =~ /redirect/ }
      if each[:scope] == :query
        para = joinPara(k_v,"=","&")
        @formatedRequest[:header].delete("content-length")
        @formatedRequest[:header].delete("accept-encoding") if @formatedRequest[:header].keys.include?("accept-encoding")

         hash  = {
            :method     => @formatedRequest[:method],
            :url        => "https://"+@formatedRequest[:host]+@formatedRequest[:uri]+"?"+para,
            :use_ssl    => true,
            :headers    => @formatedRequest[:header],
        }

        response = send_http_request(hash)[:data]

        if response.code == "302"

         if response.to_hash["location"] =~ /http:\/\/www.abc.com/
           return {
                    :name => "redirect parameter bypass",
                    :state => true,
                    :vector => hash[:url],
                    :echo => "location: #{response.to_hash["location"]}"
           }
         end
        end

        if response.code == "200"
          if response.body =~ /http:\/\/www.abc.com/
            return {
                :name => "redirect parameter bypass",
                :state => true,
                :vector => hash[:url],
                :echo => "#{$~.to_s}"
            }
          end
        end

      end

      if each[:scope] == :para
        para = joinPara(k_v,"=","&")
        @formatedRequest[:header]["content-length"] = para.size.to_s
        @formatedRequest[:header].delete("accept-encoding") if @formatedRequest[:header].keys.include?("accept-encoding")

        hash  = {
            :method     => @formatedRequest[:method],
            :url        => "https://"+@formatedRequest[:host]+@formatedRequest[:uri],
            :use_ssl    => true,
            :post_body  => para,
            :headers    => @formatedRequest[:header],
        }

        response = send_http_request(hash)[:data]
        if response.code == "302"
          if response.to_hash["location"] =~ /http:\/\/www.abc.com/
            return {:name => "redirect parameter bypass",:state => true, :vector => hash[:url], :echo => "location: #{response.to_hash["location"]}"}
          end
        end

        if response.code == "200"
          if response.body =~ /http:\/\/www.abc.com/
            return {:name => "redirect parameter bypass",:state => true, :vector => hash[:url], :echo => "#{$~.to_s}"}
          end
        end
      end

    }
    {:name => "redirect parameter bypass",:state => false, :vector => "null", :echo => "null"}

  end

  def effectiveLogoutCheck(data)
    @formatedRequest[:header].delete("accept-encoding") if @formatedRequest[:header].keys.include?("accept-encoding")

    hash  = {
        :method     => @formatedRequest[:method],
        :url        => "https://"+@formatedRequest[:host]+@formatedRequest[:uri],
        :use_ssl    => true,
        :post_body  => @formatedRequest[:body],
        :headers    => @formatedRequest[:header],
    }

    fstPost = send_http_request(hash)

    @formatedRequest[:header]["content-length"] = "para".size.to_s
    hash[:url]      = "https://"+@formatedRequest[:host]+"/index.html"
    hash[:headers]["cookie"] = hash[:headers]["cookie"][0..-2]
    hash[:post_body]= "para"
    sndPost = send_http_request(hash)
    sndPost[:data].message

    if sndPost[:data] == "200"
      if fstPost.body == sndPost.body
         {:name => "uneffective logout",:state => true, :vector => hash[:url], :echo => "#{sndPost.body}"}
      end
         {:name => "effective logout",:state => false, :vector => hash[:url], :echo => ""}
    else
      {:name => "effective logout check failed and check menual please",:state => true, :vector => hash[:url], :echo => "#{$~.to_s}"}
    end
  end

  def isPhoneRegistered(data)
    original_hash  = {
        :method     => @formatedRequest[:method],
        :url        => "https://"+@formatedRequest[:host]+@formatedRequest[:unparsed_uri],
        :use_ssl    => true,
        :headers    => @formatedRequest[:header],
        :post_body  => @formatedRequest[:body],
    }
    # original_http_response = send_http_request(original_hash)
    data.each{|each|
      k_v = @formatedRequest[each[:scope]]
      if each[:scope] == :query
        k_v.each{|k,v|   k_v[k] = '13911941176' if k == each[:name] }
        para_registered = joinPara(k_v,"=","&")
        @formatedRequest[:header].delete("accept-encoding") if @formatedRequest[:header].keys.include?("accept-encoding")

        registered_hash  = {
            :method     => @formatedRequest[:method],
            :url        => "https://"+@formatedRequest[:host]+@formatedRequest[:uri]+"?"+para_registered,
            :use_ssl    => true,
            :headers    => @formatedRequest[:header],
            :post_body  => @formatedRequest[:body],
        }

        k_v.each{|k,v|   k_v[k] = '13800138000' if k == each[:name] }
        para_unknown_registered = joinPara(k_v,"=","&")

        unknown_registered_hash  = {
            :method     => @formatedRequest[:method],
            :url        => "https://"+@formatedRequest[:host]+@formatedRequest[:uri]+"?"+para_unknown_registered,
            :use_ssl    => true,
            :headers    => @formatedRequest[:header],
            :post_body  => @formatedRequest[:body],
        }
        # response = send_http_request(unregistered_hash)[:data]
      elsif each[:scope] == :para
        k_v.each{|k,v|   k_v[k] = '13911941176' if k == each[:name] }
        para_registered = joinPara(k_v,"=","&")
        @formatedRequest[:header].delete("accept-encoding") if @formatedRequest[:header].keys.include?("accept-encoding")
        registered_hash  = {
            :method     => @formatedRequest[:method],
            :url        => "https://"+@formatedRequest[:host]+@formatedRequest[:unparsed_uri],
            :use_ssl    => true,
            :headers    => @formatedRequest[:header],
            :post_body  => para_registered,
        }

        k_v.each{|k,v|   k_v[k] = '13800138000' if k == each[:name] }
        para_unknown_registered = joinPara(k_v,"=","&")

        unknown_registered_hash  = {
            :method     => @formatedRequest[:method],
            :url        => "https://"+@formatedRequest[:host]+@formatedRequest[:unparsed_uri],
            :use_ssl    => true,
            :headers    => @formatedRequest[:header],
            :post_body  => para_unknown_registered,
        }
      else
        return     {:name => "Phone Registered Check",:state => true, :vector => "null", :echo => "undefined 'scope' data"}
      end
      response_for_registered         = send_http_request(registered_hash)
      response_for_unknown_registered = send_http_request(unknown_registered_hash)
      if response_for_registered[:data].body == response_for_unknown_registered[:data].body
        return {:name => "Phone Registered Check",:state => false, :vector => "null", :echo => "same response body"}
      else
        return {:name => "Phone Registered Check",:state => true, :vector => joinPara(k_v,"=","&"), :echo => response_for_unknown_registered[:data].body }
      end
    }
  end

  def brokenSessionCheck(data)
    p "isPhoneRegistered"
  end

  def plainPasswdCheck(data)
    data.each{|each|
      pwd = @formatedRequest[each[:scope]][each[:name]]
         unless pwd =~ /[0-9a-f]{32}/
           return {:name => "plain Passwd Check",:state => true, :vector => "NULL", :echo => "It is seem that users could post a plain password in this request."}
         end
    }
    return {:name => "plain Passwd Check",:state => false, :vector => "NULL", :echo => "No plain password in this request."}
  end

  def crossDomainRiskCheck(data)
    {:name => "cross Domain Risk Check",:state => true, :vector => "NULL", :echo => "cookies hava a cross-domain risk"}
  end

  def methodname(data)
    {:name => "methodname",:state => false, :vector => "NULL", :echo => "this is a test"}
  end


end

class ResponseBasedAnalyzer
  def initialize()

  end
end

class BasicAnalyzer

  def initialize(formatedRequest)
    @formatedRequest = formatedRequest
    @original_hash  = {
        :method     => @formatedRequest[:method],
        :url        => "https://"+@formatedRequest[:host]+@formatedRequest[:unparsed_uri],
        :use_ssl    => true,
        :headers    => @formatedRequest[:header],
        :post_body  => @formatedRequest[:body],
    }
  end

  def joinPara(hash,jointer,separator)
    catch = []
    hash.each{|key,value|    catch << "#{key}#{jointer}#{value}"}
    catch.join(separator)
  end

  def paraSetEmpty
    query_white_list  = ["fr"]
    para_white_list   = ["_h","ct"]
    original_http_response = send_http_request(@original_hash)
    set = []
    # query
    query_hash  = @formatedRequest[:query]
    query_hash.each{|key,value|
      next if query_white_list.include?(key)
      catch = query_hash
      catch.delete(key)
      query_string = joinPara(catch,"=","&")
      hash = @original_hash
      hash[:url] = "https://"+@formatedRequest[:host]+@formatedRequest[:uri]+"?"+query_string
      response = send_http_request(hash)
      if original_http_response[:data].body == response[:data].body
        set << {:type => "query", :name => key, :value => value}
      end
    }
    para_hash   = @formatedRequest[:para]
    para_hash.each{|key,value|
      next if para_white_list.include?(key)
      catch = para_hash
      catch.delete(key)
      para_string = joinPara(catch,"=","&")
      hash = @original_hash
      hash[:post_body] = para_string
      response = send_http_request(hash)
      if original_http_response[:data].body == response[:data].body
        set << {:type => "post", :name => key, :value => value}
      end
    }
    if set.size > 0
      catch = {"query" => {}, "post" => {}}
      set.each{|each|
        catch["query"].store(each[:name],each[:value]) if each[:type] == "query"
        catch["post"].store(each[:name],each[:value]) if each[:type] == "post"
      }
      s = JSON::pretty_generate catch
      # puts s
      {:name => "Uneffective query parameters check",:state => true, :vector => s, :echo => "Some query parameters may not be useful."}
    else
      {:name => "Uneffective query parameters check",:state => false, :vector => "NULL", :echo => "NULL"}
    end

  end

end
