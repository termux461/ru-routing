<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Routing.php';
require dirname(__DIR__).'/src/Sources.php';
require dirname(__DIR__).'/src/VpnCatalog.php';
use function RuRouting\{vpnServices,telegramIpv4,vpnExports};
function checkVpn(bool $condition,string $message): void { if(!$condition) throw new RuntimeException($message); }
function rejectsVpn(callable $fn): bool { try {$fn();return false;}catch(Throwable) {return true;} }
$valid="91.108.56.0/22\n91.108.4.0/22\n149.154.160.0/20\n185.76.151.0/24\n2001:67c:4e8::/48\n";
$networks=telegramIpv4($valid);
checkVpn(count($networks)===4 && in_array('149.154.160.0/20',$networks,true),'official IPv4 parsed; IPv6 omitted');
checkVpn(rejectsVpn(fn()=>telegramIpv4("91.108.56.0/22\n")),'short Telegram feed must fail');
checkVpn(rejectsVpn(fn()=>telegramIpv4($valid."0.0.0.0/0\n")),'default route must fail');
checkVpn(rejectsVpn(fn()=>telegramIpv4($valid."10.0.0.0/8\n")),'private ranges must fail');
checkVpn(rejectsVpn(fn()=>telegramIpv4($valid."8.0.0.0/8\n")),'overly broad ranges must fail');
$services=vpnServices('{"telegram":{"name":"Telegram","domains":["telegram.org"]},"youtube":{"name":"YouTube","domains":["youtube.com","ytimg.com"]}}');
checkVpn(rejectsVpn(fn()=>vpnServices('{"youtube":{"name":"YouTube","domains":["youtube.com"]}}')),'Telegram required');
checkVpn(rejectsVpn(fn()=>vpnServices('{"telegram":{"name":"T","domains":["a.ru"]},"dup":{"name":"D","domains":["a.ru"]}}')),'duplicate domain rejected');
$fake=fn($host)=>match($host){'telegram.org'=>['149.154.167.99'],'youtube.com'=>['142.250.1.1','8.8.8.8'],'ytimg.com'=>[],default=>[]};
$files=vpnExports($services,$networks,$fake,[],'2026-11-01T00:00:00+00:00');
$catalog=json_decode($files['vpn-catalog.json'],true,512,JSON_THROW_ON_ERROR);
$entries=json_decode($files['vpn-list.json'],true,512,JSON_THROW_ON_ERROR);
checkVpn($catalog['mode']==='selected-through-vpn','explicit direction');
checkVpn(count($entries)===6 && $catalog['domain_categories']['149.154.160.0/20']==='telegram','Telegram CIDR belongs to Telegram group');
checkVpn(in_array(['hostname'=>'149.154.160.0/20','ip'=>'149.154.160.0/20','ips'=>['149.154.160.0/20']],$entries,true),'CIDR stored for Amnezia');
checkVpn($catalog['domain_categories']['youtube.com']==='youtube','YouTube group');
$sing=json_decode($files['vpn-sing-box.json'],true,512,JSON_THROW_ON_ERROR);
checkVpn(in_array('149.154.160.0/20',$sing['rules'][0]['ip_cidr'],true) && in_array('142.250.1.1/32',$sing['rules'][0]['ip_cidr'],true),'CIDR vs host routes');
checkVpn(!in_array('149.154.160.0/20',$sing['rules'][0]['domain_suffix'],true),'CIDR is not a domain');
checkVpn(str_contains($files['vpn-clash.yaml'],"IP-CIDR,149.154.160.0/20,no-resolve"),'Clash CIDR');
checkVpn(str_contains($files['vpn-ipv4.txt'],'8.8.8.8/32'),'non-Russian addresses are allowed');
$report=json_decode($files['vpn-report.json'],true,512,JSON_THROW_ON_ERROR);
checkVpn($report['skip_reasons']['ytimg.com']==='no_a_record' && $report['telegram_ipv4_networks']===4,'report records missing addresses');
checkVpn(rejectsVpn(fn()=>vpnExports($services,$networks,fn()=>[])),'failed DNS cannot clobber working list');
$real=vpnServices(file_get_contents(dirname(__DIR__).'/sources/vpn-services.json'));
checkVpn(isset($real['telegram'],$real['youtube'],$real['meta']),'expected popular services');
echo "OK: VPN-only generation and safety checks\n";
