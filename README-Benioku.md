# Linux-Tools

TR:
Sysprep, bir sanal makineyi sıfırlayabilir veya çoğu yapılandırmasını kaldırabilir, böylece ondan klonlar yapılabilirsiniz. 
Bu süreçteki adımlar, SSH ana bilgisayar anahtarlarının kaldırılmasını, Ağ MAC yapılandırmasının kaldırılmasını ve kullanıcı hesaplarının silinmesini içerir. 

Sysprep can reset a virtual machine or remove most of its configurations so you can make clones from it. 
The steps in this process include removing SSH host keys, 
removing network MAC configuration, and deleting user accounts.

WARNING

Using virt-sysprep in live virtual machines or at the same time as other disk editing tools can be dangerous and cause disk corruption. Before using this command, the virtual machine must be shut down and disk images must not be edited at the same time. you should also have a solid backup before proceeding.

virt-sysprep’i canlı sanal makinelerde veya diğer disk düzenleme araçlarıyla aynı anda kullanmak tehlikeli olabilir ve disk bozulmasına neden olabilir. 
Bu komutu kullanmadan önce sanal makine kapatılmalıdır ve disk görüntüleri aynı anda düzenlenmemelidir. 
ayrıca işlemden önce sağlam bir yedeğinizin olması gerekir.




TR: linux-sysprep
=======================
2 .sh komut dosyası içerir.
RİSK: Komutları çalıştırmadan önce bir yedeğiniz olduğundan emin olun!!
RİSK: Komutları çalıştırmadan önce kesinlikle emin olun!!
'linux-sysprep.sh' benzer bir amaç için kullanılması amaçlanan küçük bir kabuk betiğidir.
Windows sistem yöneticileri tarafından kullanılan 'sysprep' aracının amacı. Çalıştırılacak
tüm sisteme özel yapılandırma verilerini kaldırın ve
diğer ana bilgisayarlarda sağlanan bir görüntü olarak kullanılmaya hazır.

Bu betiği çalıştırmak, sistemi bir sonraki sefere kadar çoğunlukla kullanılamaz hale getirir.
önyükleme yapar, bu nedenle sistemi çalıştırdıktan sonra kapatmanız şiddetle tavsiye edilir.
O IS.

Sorumluluk Reddi: Şu anda bu komut dosyası yalnızca RHEL7'de kullanım için test edilmiştir.
oVirt sanallaştırma ortamının üzerinde sağlanan sistemler. muhtemelen
benzer CentOS ve Fedora sistemlerinde iyi çalışacaktır. Ayrıca olmayacak
diğer Linux sistemlerinde patlayabilir ancak istenen sonucu elde edemeyebilir.
işlevsellik.

Diğer Linux sürümleriyle uyumluluğu geliştirmeye yönelik yamalar memnuniyetle karşılanmaktadır!





EN:
linux-sysprep
=======================
Contains 2 .sh scripts.
RISK: Make sure you have a backup before executing commands!!
RISK: Be absolutely sure before executing commands!!
'linux-sysprep.sh' is a small shell script intended to be used for a similar purpose.
Purpose of the 'sysprep' tool used by Windows system administrators. It is to be run
remove all system specific configuration data and
ready to be used as an image provided on other hosts.

Running this script makes a system mostly unusable until the next time.
it boots, so it is highly recommended to shut down the system after running it.
HE IS.

Disclaimer: Currently this script is only tested for use on RHEL7.
Systems provisioned above the oVirt virtualization environment. probably
it will work fine on similar CentOS and Fedora systems. Also it won't be
on other Linux systems it may explode but not achieve the desired result.
functionality.

Patches to improve compatibility with other Linux versions are welcome!
