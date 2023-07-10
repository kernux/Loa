# Loa
本项目是基于SysWhisper(https://github.com/jthuraisamy/SysWhispers2)提供的系统调用文件编写的shellLoader工具

## 使用说明

### 生成CS的payload文件

![](https://github.com/L4ml3da/Loa/master/img/cs_payload.jpg)

### 生成含有shellcode的图片

1、将payload.bin和随意一张1.jpg图片放在同目录下，运行生成test.jpg

![](https://github.com/L4ml3da/Loa/master/img/page.jpg)

2、将test.jpg图片放到vps上供shellLoader加载

Python3 -m http.server 9091

### 编译shellLoader

1、修改Loa.cpp中图片下载地址

![](https://github.com/L4ml3da/Loa/master/img/loa.jpg)

2、编译shellLoader，详细编译方法请参考syswhisper项目中的说明

![](https://github.com/L4ml3da/Loa/master/img/complie.jpg)

## 免责申明

本项目仅供学习交流使用，请勿用于违法犯罪行为。

本软件不得用于从事违反中国人民共和国相关法律所禁止的活动，由此导致的任何法律问题与本项目和开发人员无关。

## 关注我们

![](https://github.com/L4ml3da/Loa/master/img/gzh.jpg)

![](https://github.com/L4ml3da/Tinker/blob/master/img/xq.jpg)