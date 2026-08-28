# 优化等级策略 —— 单一事实来源
#
# configure.ac 与 scripts/build-static.sh 都 source 本文件，改这里即可全局生效，
# 不要把 -O 等级散落到各个 Makefile.am 或构建脚本里。
#
# 分档依据是组件在数据通路上的位置，不是"重要程度"：
#
#   CRYPTO  每字节都要过。实测 ChaCha20 在 -Os / -O2 下代码体积相同，
#           但 -O2 快约 9%（2889 -> 3139 MB/s）；-O3 再快 3%（-> 3242），
#           代价 2.7K，值得。
#   HOT     每个事件或每个数据包过一次：ss 自身的收发转发、libev 事件循环。
#   COLD    每条连接至多过一次：pcre 的 ACL 规则匹配、c-ares 的域名解析。
#           这里降到 -Os 省下的体积不换任何吞吐。
#
# 注：libcork / libipset / libbloom 是 submodule 且自身没有 AM_CFLAGS，
# 只能跟随全局 CFLAGS（即 HOT），合计约 18.6K，不值得为其改动子模块。

SS_OPT_CRYPTO="-O3"
SS_OPT_HOT="-O2"
SS_OPT_COLD="-Os"

# 与优化等级无关、所有组件共用的开关。
# -ffunction-sections/-fdata-sections 必须编译期就加，否则链接时的
# --gc-sections 在库内部使不上劲。
SS_CFLAGS_COMMON="-fno-pie -ffunction-sections -fdata-sections"
