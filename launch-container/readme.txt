
########################################
端口映射出来：32015/32015
开启CSVNode机密容器：start_csvnode.sh
关闭CSVNode机密容器：stop_csvnode.sh

export KUBECONFIG=/etc/kubernetes/admin.conf
查看Pod机密容器是否开启：kubectl get pods
能看到csvnode-ra在Running

开启后进入CSVNode机密容器：kubectl exec -it csvnode-ra -- bash
机密容器内证明代码路径为/root/attestation （映射到主机/opt/hygon/csv/attestation，在主机进行开发修改即可）

########################################
注册相关证书获取，路径为：/opt/csv，证书为hrk、hsk、cek和pek
注册时使用固定IP和端口，即192.168.88.64和32015

########################################
证明相关代码路径：/opt/hygon/csv/attestation
注意证明代码编译使用的是gmssl库，Makefile中指定为
LIBDIR = /opt/gmssl/lib/
INCDIR = /opt/gmssl/include/
在机密容器内获取证明报告：ioctl_get_attestation.c
验证证明报告：verify_attestation.c
编写验证库时，里面函数会自动从CSV官网下载证书，可以禁用掉，使用本地已经下载下来的
注意openssl与gmssl的冲突
注意在映射的路径中编写代码和保留长存数据，不然机密容器代码实例关闭后，修改会丢失（内存中没有落盘），映射进去的路径是落盘的