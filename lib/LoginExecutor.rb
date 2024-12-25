module LoginCommands

      private

      def login()
            response = @session.post('https://steamcommunity.com/login/getrsakey/', { 'username' => @username }).content
            data = pass_stamp(response, @password)
            encrypted_password = data["password"]
            timestamp = data["timestamp"]

            send = {
              'password' => encrypted_password,
              'username' => @username,
              'twofactorcode' => '',
              'emailauth' => '',
              'loginfriendlyname' => '',
              'captchagid' => '-1',
              'captcha_text' => '',
              'emailsteamid' => '',
              'rsatimestamp' => timestamp,
              'remember_login' => @remember
            }

            login = @session.post('https://steamcommunity.com/login/dologin', send).content
            firstreq = JSON.parse(login)

            raise "Incorrect username or password" if firstreq["message"] == "The account name or password that you have entered is incorrect."

            until firstreq["success"] == true
                  sleep(0.3)
                  gid = '-1'
                  cap = ''
                  if firstreq['captcha_needed'] == true
                        gid = firstreq['captcha_needed']
                        File.delete("./#{@username}_captcha.png") if File.exist?("./#{@username}_captcha.png")
                        @session.get("https://steamcommunity.com/login/rendercaptcha?gid=#{gid}").save "./#{@username}_captcha.png"
                        puts @session.get("https://steamcommunity.com/login/rendercaptcha?gid=#{gid}").content
                        puts "you need to write a captcha to continue"
                        puts "there is an image named #{@username}_captcha in the script directory"
                        puts "open it and write the captcha here"
                        cap = gets.chomp
                  end

                  emailauth = ''
                  facode = ''
                  emailsteamid = ''
                  if firstreq['requires_twofactor'] == true
                        if @secret.nil?
                              puts "write 2FA code"
                              facode = gets.chomp
                        else
                              facode = fa(@secret, @time_difference)
                        end
                  elsif firstreq['emailauth_needed'] == true
                        emailsteamid = firstreq['emailsteamid']
                        puts "Guard code was sent to your email"
                        puts "write the code"
                        emailauth = gets.chomp
                  end

                  send = {
                    'password' => encrypted_password,
                    'username' => @username,
                    'twofactorcode' => facode,
                    'emailauth' => emailauth,
                    'loginfriendlyname' => '',
                    'captchagid' => gid,
                    'captcha_text' => cap,
                    'emailsteamid' => emailsteamid,
                    'rsatimestamp' => timestamp,
                    'remember_login' => @remember
                  }

                  output "attempting to login"
                  login = @session.post('https://steamcommunity.com/login/dologin', send).content
                  firstreq = JSON.parse(login)
            end

            response = firstreq

            if @steamid && @steamid != response["transfer_parameters"]["steamid"]
                  puts "the steamid you provided does not belong to the account you entered"
                  puts "steamid will be overwritten"
                  @steamid = response["transfer_parameters"]["steamid"]
            else
                  @steamid = response["transfer_parameters"]["steamid"]
            end

            response["transfer_urls"].each do |url|
                  @session.post(url, response["transfer_parameters"])
            end

            steampowered_sessionid = ''
            @session.cookies.each do |c|
                  steampowered_sessionid = c.value if c.name == "sessionid"
            end

            cookie = Mechanize::Cookie.new domain: 'steamcommunity.com', name: 'sessionid', value: steampowered_sessionid, path: '/'
            @session.cookie_jar << cookie
            @loggedin = true

            begin
                  text = Nokogiri::HTML(@session.get("https://steamcommunity.com/dev/apikey").content).css('#bodyContents_ex').css('p').first.text.split(' ')
                  @api_key = text[1] unless text.include?('Registering for a Steam Web API Key will enable you to access many Steam features from your own website')
            rescue
                  output "Could not retrieve api_key"
            end

            if @api_key
                  data = get_player_summaries(@steamid)
                  data.each do |element|
                        @persona = element["personaname"] if element["steamid"].to_s == @steamid.to_s
                  end
            end

            output "logged in as #{@persona}"
            output "your steamid is #{@steamid}"
            output "loaded API_KEY: #{@api_key}" if @api_key
      end

      def pass_stamp(give, password)
            data = JSON.parse(give)
            mod = data["publickey_mod"].hex
            exp = data["publickey_exp"].hex
            timestamp = data["timestamp"]

            asn1 = OpenSSL::ASN1::Sequence([
                                             OpenSSL::ASN1::Integer(mod),
                                             OpenSSL::ASN1::Integer(exp)
                                           ])
            rsa_key = OpenSSL::PKey::RSA.new(asn1.to_der)

            ep = Base64.encode64(rsa_key.public_encrypt(password.encode("utf-8"))).gsub("\n", '')
            { 'password' => ep, 'timestamp' => timestamp }
      end

end
