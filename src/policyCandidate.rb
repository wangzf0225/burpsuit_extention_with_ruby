#CONDITIONS

#ACTIONS
NULL                        = 0 #Do not use any policy
INCLUDE_IN_KEYS             = 1 #use policy in keys[]
INCLUDE_IN_VALUES           = 2 #Use polisy in values[]
MATCH_KEY_WORDS_IN_VALUE    = 4 #Use polisy in String. NOTICE:When you choice this option,':condition' hava to have a value who has only one element.
MATCH_KEY_WORDS_IN_NAME     = 8 #Use polisy in String. NOTICE:When you choice this option,':condition' hava to have a value who has only one element and it must be '[:qury, :para]'

# POLICY

# name will display on tab
# scope is used to specify scope where extender use this policy
# condition means keyword or keywords Array
# action tells extender which method will be used
# method is StateMachine::methodname

DATA = [
    {
        :name       => "redirect parameters check",
        :scope      => [:query,:para],
        :condition  => ["redirect","redirect_uri"],
        :action     => INCLUDE_IN_KEYS,
        :method     => :redirectParameterCheck
    },

    # It will check logout if there is 'logout' keyword in uri
    {
        :name       => "effective_logout_check",
        :scope      => [:uri],
        :condition  => ["logout"],
        :action     => MATCH_KEY_WORDS_IN_VALUE,
        :method     => :effectiveLogoutCheck
    },

    # It will check logout if there is 'logout' keyword in get or post parameters' values.
    {
        :name       => "effective_logout_check",
        :scope      => [:query,:para],
        :condition  => ["logout"],
        :action     => INCLUDE_IN_VALUES,
        :method     => :effectiveLogoutCheck
    },


    {
        :name       => "phone_registered_check",
        :scope      => [:query, :para],
        :condition  => ["phone","mobile","account","phone_number","phonenumber","phonenum"],
        :action     => INCLUDE_IN_KEYS,
        :method     => :isPhoneRegistered,
    },


    {
        :name       => "Broken Session Management",
        :scope      => [:query,:para],
        :condition  => ["s_id", "sid", "sess_id","sessid","session","sessionid","session_id"],
        :action     => INCLUDE_IN_KEYS,
        :method     => :brokenSessionCheck,
    },

    # plain password check

    {
        :name       => "plain passsword check",
        :scope      => [:query,:para,:cookies],
        :condition  => ["password","passwd","pwd"],
        :action     => INCLUDE_IN_KEYS,
        :method     => :plainPasswdCheck,
    },


    {
        :name       => "cross domain risk check",
        :scope      => [:cookies],
        :condition  => ["domain"],
        :action     => INCLUDE_IN_KEYS,
        :method     => :crossDomainRiskCheck,
    },


    {
        :name       => "find wanted parameter name",
        :scope      => [:query, :para],
        :condition  => [/(ount)|(momoid)/],
        :action     => MATCH_KEY_WORDS_IN_NAME,
        :method     => :methodname,
    },

    # {
    #     :name       => "",
    #     :scope      => [],
    #     :condition  => [],
    #     :action     => CONT,
    #     :method     => :methodname,
    # },
]