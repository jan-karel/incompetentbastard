#!/usr/bin/env bash
# Jan-Karel Visser
# LGPLv3 licensed
# https://jan-karel.nl
# https://hacksec.nl

source meuk/globalmeuk.sh

#adjust to your needs
#commonpasswords=('admin' 'administrator' 'beheer' 'helpdesk' 'support' 'guest' 'nimda' 'lente' 'zomer' 'herfst' 'winter' 'spring' 'summer' 'winter' 'autumn' 'password' 'p4ssw0rd' 'p@ssw0rd' 'welcome' 'welkom' 'qwerty' '1q2w3e')


commonpasswords=('admin' 'administrator' 'nimda' 'lente' 'helpdesk' 'support' 'guest' 'spring' 'summer' 'winter' 'autumn' 'password' 'p4ssw0rd' 'p@ssw0rd' 'welcome' 'welkom' 'qwerty' '1q2w3e')

#reset the password lists, insert blanc password
echo '' > meuk/wordlists/passwords.txt


#echo date+%Y

echo "[*] Incompentent Bastard v${VERSIE}"
echo "[.] Creating variations on ${#commonpasswords[@]} common passwords..."
for x in ${commonpasswords[@]}; do

	echo $x >> meuk/wordlists/passwords.txt
	echo ${x^} >> meuk/wordlists/passwords.txt


	for y in '!' '@' '#' '$'; do

		for tt in $(date +'%Y') $(date +'%y'); do

			echo ${x}${tt} >> meuk/wordlists/passwords.txt
			echo ${x^}${tt} >> meuk/wordlists/passwords.txt
			echo ${x}${tt}$y >> meuk/wordlists/passwords.txt
			echo ${x^}${tt}$y >> meuk/wordlists/passwords.txt

		done 
		
			echo $x$y >> meuk/wordlists/passwords.txt
			echo ${x^}$y >> meuk/wordlists/passwords.txt
	done
	for f in 1 2 3 04 05 06 07 08 007 008 009 42 69 88 444 555 666; do

		echo "${x}0${f}" >> meuk/wordlists/passwords.txt
		echo "${x^}0${f}" >> meuk/wordlists/passwords.txt
		echo "${x}${f}" >> meuk/wordlists/passwords.txt
		echo "${x^}${f}" >> meuk/wordlists/passwords.txt


		for fy in '!' '@' '#' '$'; do

		echo "${x}0${f}${fy}" >> meuk/wordlists/passwords.txt
		echo "${x^}0${f}${fy}" >> meuk/wordlists/passwords.txt


		done



	done 


done
#cleanup 
gawk -i inplace '!a[$0]++' meuk/wordlists/passwords.txt
echo "[+] Passwords generated $(wc -l meuk/wordlists/passwords.txt) Have a nice day!"
