# Burp Extension

#
# Command line example:
# JRUBY_HOME=${MY_RUBY_HOME} java -XX:MaxPermSize=1G -Djsse.enableSNIExtension=false -Xmx1g -Xms1g -jar ${path of burpsuite}

require "java"
require "json"
require "uri"
require "webrick"

java_import 'burp.IBurpExtender'
java_import 'burp.IMessageEditorTabFactory'
java_import 'burp.IMessageEditorTab'
java_import 'burp.IRequestInfo'
java_import 'burp.IIntruderPayloadProcessor'
java_import 'burp.IHttpListener'

EXTENDER_NAME = "M_API Audit Tool"
DISPLAY_NAME  = "Auditor"
PATH          = File.dirname($LOAD_PATH[0])+"/"

# load "#{PATH}/lib.class.rb"
# load "#{PATH}/lib.function.rb"

load "#{PATH}src/lib.function.rb"
load "#{PATH}src/lib.class.rb"

class BurpExtender
  include IBurpExtender
  include IMessageEditorTabFactory
  # include IHttpListener


  attr_reader :callbacks

  # void IBurpExtender::registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
  def registerExtenderCallbacks(callbacks)

    @callbacks = callbacks
    @stderr = callbacks.get_stderr()
    @stdout = java.io.PrintWriter.new(callbacks.getStdout(), true)
    @helper = callbacks.get_helpers()
    @@loader = ""
    makelog "load a new extender and register self"

    begin
      callbacks.setExtensionName(EXTENDER_NAME)
      callbacks.registerMessageEditorTabFactory(self)
      # callbacks.registerHttpListener(self)
    rescue
      @stderr.write(" error: #{$!} at#{$@}\n".to_java_bytes)
    end
  end


  # IMessageEditorTab IMessageEditorTabFactory::createNewInstance(
  #   IMessageEditorController controller,
  #   boolean editable)
  def createNewInstance(controller, editable)
    AuditTab.new(@callbacks, editable)
  end


end

class AuditTab
  include IMessageEditorTab
  include IHttpListener
  # include IMessageEditorController

  def initialize(callbacks, editable)
    @stderr = callbacks.get_stderr()
    @helper = callbacks.get_helpers()
    @txt_input = callbacks.create_text_editor()
    @editable = editable
    @stdout = java.io.PrintWriter.new(callbacks.getStdout(), true)
    @callbacks = callbacks
  end


  ################
  # Burp Methods #
  ################

  # String IMessageEditorTab::getTabCaption();
  def getTabCaption
    DISPLAY_NAME
  end

  # java.awt.Component IMessageEditorTab::getUiComponent()
  def getUiComponent
    @txt_input.get_component()
  end

  # boolean IMessageEditorTab::isEnabled(byte[] content, boolean isRequest)
  def isEnabled(content, isRequest)
    true
  end

  # void IMessageEditorTab::setMessage(byte[] content, boolean isRequest)
  def setMessage(content, isRequest)

      @txt_input.text = "Text is not Modified.".to_java_bytes if @txt_input.textModified

    if isRequest
      makelog "start request audit"
      @txt_input.text = "HTTP Request is nil or empty.".to_java_bytes  if content.nil? or content.empty?
      resultlist = []
      begin
        formatedRequest = parse_request(content.to_s)
        checklist = conduct_policy(formatedRequest)
        resultlist += lunchRequestBasedAudit(checklist,formatedRequest)
        basic = BasicAnalyzer.new(formatedRequest)
        # resultlist << basic.paraSetEmpty
        display_data = dataEdit(resultlist)
        display_data.size
        if display_data.size > 0
          @txt_input.text = display_data.to_java_bytes
        else
          @txt_input.text = "Nothing to display".to_java_bytes
        end
      rescue
        @stderr.write(" error: #{$!} at#{$@}\n".to_java_bytes)
      end

    else
      @txt_input.text = "HTTP Reponse is nil or empty.".to_java_bytes  if content.nil? or content.empty?

      lines= content.to_s.split("\n")
      body = ""
      lines.each_with_index{|each,index|  body = each if each.chomp =~ /^\{.*\}$/  }
      if body.size > 0
        body   = body.chomp
        begin
          hash = JSON.parse body
          body = JSON.pretty_generate hash
        rescue
          @stderr.write(" error: #{$!} at#{$@}\n".to_java_bytes)
        end
        @txt_input.text = body.to_java_bytes
      else
        @txt_input.text = content.to_s.to_java_bytes
      end
    end
    @txt_input.editable = @editable

  end

  # byte[] IMessageEditorTab::getMessage()
  def getMessage
    isRequest = @txt_input.text[0..3].to_s == "HTTP"
    # @callbacks.issueAlert(@txt_input.text[0..5])
    if isRequest
      info = @helper.analyze_request(@txt_input.text)
    else
      info = @helper.analyze_response(@txt_input.text)
    end
    headers = @txt_input.text[ 0..(info.get_body_offset - 1) ].to_s
    body = @txt_input.text[ info.get_body_offset..-1 ].to_s
    return "this is a test text".to_java_bytes
  end

  # boolean IMessageEditorTab::isModified()
  def isModified
    return @txt_input.text_modified?
  end
end