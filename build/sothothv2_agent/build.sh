#!/bin/bash

set -e

#写一个monitor进程的代码，为了方便跨平台，使用go语言静态编译，要求如下:
#1、该进程为守护进程，同时也是一个Agent进程，默认为后台执行，但提供参数可以在前台运行；
#2、默认日志为info级别，但启动时提供日志级别和日志的参数设置；
#3、进程运行时提供工作空间（指定的目录）的输入参数、Server端的项目ID、Server的地址和端口、以及monitor作为Agent的UUID参数，
#4、该进程有一个配置文件，配置文件为ini文本，进程运行时优先检、查配置文件是否存在，如果存在将使用配置文件作为入参，忽略所有程序参数；如果配置文化不存在，则将程序的入参写入配置文件中，此时工作空间、Server端的项目ID、Server地址和端口为必选项，其他为可选项，UUID未指定是自动生成一个；
#5、进程运行时将检查工作空间下的service_config目录，如果不存在就创建，如果该目录下有后缀为_service.json的文件,则认为是一个服务的定义文件；
#6、请设计服务的定义文件，要求如下：
#a、要求定义服务的拉起命令（必选）、关闭命令（可选）、重启命令（可选）、PID文件（必选）、两种日志文件（stderr、stdout）（可选）、服务的工作目录、以及montior的监控模式；
#b、monitor的监控模式分为两种，第一种是PID文件由服务自己写入，第二种是PID文件由monitor写入（此种场景下服务在前台运行）
#c、关闭命令如果没有被定义，则实现方式为获取PID文件定义的PID并直接杀死，PID文件不存在或者定义的PID不存在时不执行关闭；
#d、两种日志文件没有指定时，默认为服务的工作目录 + log目录 +  两类日志文件；
#7、在monitor进程启动后，启动服务时，将monitor进程的配置文件，以环境变量的方式注入到服务中；
#8、每隔10S监控服务的PID运行状态，如果连续6次服务都不在运行状态，则执行重启流程：如果定义了重启命令，则直接调用重启命令，如果没有定义，则重启时先关闭服务，然后拉起服务；
#9、拉起服务时，将服务的stderr和stdout重定向到日志文件中；
#10、服务的拉起顺序，按照服务定义的文件名顺序进行拉起；
#
#给出代码之后，请给出编译所需要的步骤和命令

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt-get -y install curl ca-certificates wget xz-utils sudo

cd /build
bash ./01-install-go.sh
export PATH=$PATH:/usr/local/go/bin
export INSTALL_DIR="${INSTALL_DIR}"
bash ./02-compile.sh

