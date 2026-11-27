/* ==========================================================================
 * aigis-dps / mfplay_proxy.c —— 发布批次 1.4.2（PRD v1.7，实现版本 v10.44）
 *
 * 业务：dps 统计。单 hook（v10.38 定稿）：
 *   hook  sub_5CAC50（敌方侧结算的受击子步骤，每次结算正好一次）
 *         入参 arg_0 = CDamageHandle*、ecx = 受击单位。身份（ai/ag/vg/vi）
 *         在 hook 内用 handle 解析：node = sub_4F4B50(mgr,handle) →
 *         [node+0Ch] 攻击者句柄 → 引擎句柄表；随后填 gf / d（DCC328）/
 *         ty（13 键重组）后发布，每次命中恰好一条。
 * 一行 JSON 经命名共享内存环形缓冲（Local\aigis_dps）转发给接收端。
 *
 * 为何换点（PRD v1.5 / FINDINGS §32）：旧查表点 sub_4F4B50 每次结算被引擎重复
 * 查询 25-83x（battle10：88458 条 prop 仅 ~78 个节点），需要 run-length 折叠兜底；
 * 4F3FA0 是三条节点创建路径（4F4250 导弹 / 4F4580 近战 / 4F48A0 技能）的唯一漏斗
 * （xref 全枚举），每伤害节点天然恰好一次 —— 去重/折叠逻辑整体删除。
 * 伤害值为入口终值（FINDINGS §33：三条创建路径全部"先算后建"），无入口后修改风险。
 *
 * hook 技法简化：参数在入口栈上全量可得 → 入口拦截（pushad 保护 + 调 report
 * + popad + jmp trampoline），不再需要 TLS 返回地址偷换，天然重入安全。
 *
 * 相对调试期（v1–v11 UDP 版，备份 mfplay_proxy.c.v11-udp.bak）的收敛：
 *   - 移除 hook1（消息总线）、spawn hook3/4、NameText hook5 及全部
 *     调试 dump（0xBC 快照 / 树头 / 栈窗口 / dps.ids 白名单 / DPS_DEBUG 日志）
 *   - 传输 UDP → 命名共享内存（v1.3）；移除读指针，单调序号对账（v1.4）；
 *     head/body 分离布局（v1.5，槽表确定性容量 + O(1) 寻址 + body 免哨兵）
 *   - 元数据解析全部内化：接收端每条都是「我方→敌方输出」，零判定只分桶
 *
 * 保留（v8 纪律原样）：
 *   - mfplay.dll 旁置代理注入（导出转发、DllMain 纪律）
 *   - 入口拦截 + prologue 校验（版本漂移保护，失败 OutputDebugStringA
 *     拒装，游戏无感知）
 *   - SEH safe_read（VirtualQuery 预检 + VEH 探针护盾，2026-11-20 崩溃定案：
 *     游戏进程 SEH 链被破坏，AV 不进 SEH 链）
 *   - resolve_handle（逆向自 sub_42DF80），升级为 1024 槽直接映射缓存
 *
 * 输出载荷（JSONL，七字段、ty 可缺省；顺序契约见 v10.29）：
 *   {"gf":20013,"ai":1469,"ag":3584,"vg":4106,"vi":4761,"d":7025,"ty":1}
 *     gf = GameFrame（dword_F51838，暂停/倍速感知时钟）
 *     ai = 攻击者 CardID（导弹事件 = owner 的 CardID，[对象+44h]）
 *     ag = 攻击者实例标识 = 句柄高 16 位 gen（导弹事件 = owner 的 gen）
 *     vg = 受击者实例标识 = 句柄高 16 位 gen
 *     vi = 受击者种类键 = 模式槽索引 = (*( *(vic+4) + 5Ch ) − 0x200000) >> 4
 *          （PatternID 函数 RVA 落 .text 模式处理区、16B 对齐；与实机点阵
 *          逐一对照验证无误；越界/不可读 = 0）
 *     d  = 伤害值 = 属性表伤害总量（sub_4F13B0(handle,&dword_DCC328)，
 *          即 HP 结算实际扣血）。唯一来源；0 = 本次未扣血，事件照发，
 *          由消费端按 d>0 过滤（v10.37）。
 *     ty = 伤害结算标志集 = 结算 hook（sub_5CAC50）入参 arg_0（CDamageHandle*）
 *          → sub_4F1E50 13 键 OR 重组取得完整 dword（纯读无副作用）。
 *          位域 bit0~21：bit0=Magic、bit6=Critical、bit7=紫档基线等，
 *          详见 FINDINGS §44。
 *          发布只发生在结算 hook，无配对环节，因此「事件缺 ty」只有
 *          ty_src=0（sub_4F1E50 序言漂移）一种成因。
 *          **可选字段恒在末位**：带/不带 ty 的事件共享稳定前缀。
 *
 * 身份解析时机（v10.38）：全部在结算 hook（sub_5CAC50）内完成。攻击者经
 *   CDamageHandle* 查 node（sub_4F4B50）取 [node+0Ch] 句柄（与引擎
 *   sub_5CBBE0 自己的解析链同源）；受击者对象 = ecx，句柄走 GetHandle
 *   只读语义。句柄可用 → ag/vg 取真 gen；不可用 → ai/ag = 0 / vg 退化
 *   为对象指针低位（同场次内稳定）。
 *
 * v10.23（2026-11-20 定案）：移除 ve（EnemyID）全链路（spawn hook / EIDM /
 *   行键读取 / RDMP 采样）与全部离线探针（VSMP/ROWP/CTNR/P404）；vi 定稿为
 *   模式槽索引。仅保留双 hook 主链路 + 环形 SHM + 前 4KB 诊断区。
 *
 * v10.24（2026-11-21）：ty 从 byte 升级为 dword。ty 实为 dword 位标志集
 *   （bit0~21，0x81=紫档+Magic、0xC1=紫档+Critical+Magic，FINDINGS §44），
 *   旧读法截断 bit≥8。仅改读取宽度，补丁序言/trampoline/配对逻辑均不动。
 *
 * v10.26（2026-11-22）：hook 引擎换 MinHook（vendor 源码 src/minhook/，BSD），
 *   初始化整体挪出 DllMain 到独立线程（init_thread_proc），DllMain 只留
 *   DisableThreadLibraryCalls + CreateThread，DETACH 清空（进程退出期 OS
 *   统一回收；代理 DLL 永不动态卸载，原 FreeLibrary 调用一并移除——它是
 *   规范明令禁止的 loader lock 重入点）。手写 trampoline/E9 补丁逻辑全删，
 *   EXPECT_PROLOGUE 预校验保留（MinHook 不做版本漂移保护）。naked hook
 *   本体不动：MinHook detour 入口栈布局 = 原函数入口（jmp 进 detour），
 *   pushad/popad + jmp [tram] 语义与手写版完全一致。装钩期线程挂起由
 *   MinHook 负责（脱离 loader lock 后才安全）。
 *
 * v10.27（2026-11-22）：导出转发改链接器转发字符串（mrexodia 技巧）。
 *   /EXPORT:MFPCreateMediaPlayer=\\.\GLOBALROOT\SystemRoot\SysWOW64\
 *   mfplay.dll.MFPCreateMediaPlayer —— loader 导入绑定层直连真身，
 *   删除手写桩全套（load_real_mfplay / Impl / naked 桩 / g_real_mfplay，
 *   约 60 行）：无自递归、无惰性竞态、真身恒为 OS 当前版本。
 *   ⚠ NT 路径不经过 WOW64 重定向，x86 进程必须显式写 SysWOW64。
 *   真身加载时机从「首次调用」提前到「进程加载代理时」——与非劫持
 *   场景一致，语义更标准。DPS 业务层零改动。
 *
 * v10.28（2026-11-22）：采纳 perfect-dll-proxy 生成代码的防漂移设计。
 *   mfplay.dll 实有 6 个导出（pefile 实测）：全量转发替代单点转发——
 *   MFPCreateMediaPlayer / MFPCreateMediaPlayerEx + 4 个 COM 导出（标
 *   PRIVATE 防误绑）；MAKE_EXPORT 宏按 _WIN64 分流 System32/SysWOW64，
 *   防 x64 误编译绑到 64 位真身。运行时行为与 v10.27 逐字节相同
 *   （转发是导出表数据，非代码），健壮性提升全部在版本漂移维度。
 *
 * v10.29（2026-11-22）：载荷组装双模板合一 + 字段顺序按语义重排。
 *   原 gf,d[,ty],ai,ag,vg,vi 两份格式串（带/不带 ty 各一）→ 单点组装，
 *   增删字段只改一处（消灭"两模板不同步"的协议漂移风险）。新顺序契约：
 *   gf → ai,ag（攻击者）→ vg,vi（受击方）→ d（伤害）→ ty（可选，末位）。
 *   可选字段恒在末位使所有事件共享稳定前缀（字节级 diff / 前缀比对友好）。
 *   JSON 对象无序语义 + 消费端均为标准解析器（Go json.Unmarshal /
 *   Python json.loads），顺序变更对 reader 零影响。
 *
 * v10.44（2026-11-27）：**崩溃修复 + 反查阶段落盘**（dump 实锤两发现）。
 *   ① 崩溃根因（Aigis_r.exe.18696.dmp，0xC0000409 fail-fast）：结算路径内
 *     OutputDebugStringA 的 DBG_PRINTEXCEPTION_C 走 SEH 分发，游戏 SEH 链
 *     损坏环境不可用——崩溃瞬间栈上有在途 DBG 记录（param1 直指 rev 消息
 *     缓冲 0x53efb8），fail-fast 经 unhandled→静默退出链触发。v10.43 的
 *     rev 打印是本项目首次在结算路径用 ODS（v10.41 keydiag 从未实际打印
 *     过：KPRT=0），故 v10.38–42 均不崩。⇒ rev/keydiag 打印改 DPS_DBG=1
 *     才开，默认关。
 *   ② 反查 0/284 根因（shm_20261127_103211）：ty=128（52F900 LABEL_41）
 *     路径 284/284 次 ident+8 RTTI=Enemy@@（et==1）——该路径 node+0xC 的
 *     ident+8 不是能力实例（疑似自节点/受击者句柄），54BC00 从未执行
 *     （own=0/anc=0 恒成立）。§13.11 反查链语义仅适用于 5AA520 能力 DOT
 *     路径候选；ty=128 归因须走受击者 +0xEC key 表（keydiag 线）。
 *     55 个 ty=1/129 事件 ai/ag 正常（3 玩家 CardID 357/2735/495）。
 *   新增：REV_AT1/ET1/ON0/NRG/A0/ANP 阶段计数 0x84/0x70/0x74/0x78/0x7C/
 *     0x80（diag_ver 7→8）；DPS_REV=0 关闭反查路径（崩溃 A/B 分割）；
 *     DPS_DBG=1 开打印。VERSION 1.4.1→1.4.2。
 *
 * v10.43（2026-11-27）：**能力实例归属反查上线**（SUB_5CBBE0_DECOMPILE
 *   §13.11 全链，实现候选 A）。why|=8 分支（攻击者非玩家系/未知——快照
 *   55 个 DOT 事件 ai=ag=0 的主因）接入游戏内建反查路径 sub_54BC00：
 *     atk_h → F4CB70 槽 ident（slot+4，新增 resolve_ident：不做 +8 代理
 *     重定向，ident+8 正是「目标实体」懒解析槽）→ ident+8 = attacker
 *     实体 → RTTI 3..6 直取 / RTTI 未知（能力实例）→ [实例+0xC] 归属 id
 *     （5687C0 注册时写入）→ 54BC00(dword_4F826E8, &id) 判活反查
 *     （map find → gen 校验 → 死亡位过滤，5 层失败链 = 游戏自身 tick
 *     门控）→ 锚点单位 → [锚点+0x44] = ai、锚点句柄>>16 = ag。
 *   伤害正在结算 ⇒ 施法者判活链必通过（52F900 LABEL_41 逐 tick
 *   54BC00(vector[0]) 走同一函数，施法者离场则 tick 根本不会发生）。
 *   54BC00 绑定带序言校验（55 8B EC 56 FF 75 08，exe 实读）。
 *   诊断：REVTRY/REVOK 0x64/0x68 + DbgView rev 样本行预算 200
 *   （RPRT 0x6C）；失败细分 why bit64 = 反查推进到实体层仍未归因。
 *   diag_ver 6→7。
 *
 * v10.42（2026-11-27）：修正 v10.41 遍历结构——快照实锤 key_ent 恒 0。
 *   依据 shm 快照 + sub_58A840/sub_4077C0 汇编逐条对照，四处偏差：
 *     ① 树根：head->_Parent（+4），误取 head->_Left（begin）；
 *     ② _Isnil：节点+0xD 字节（byte1），误查 +0xC byte0；
 *     ③ flag：节点+0x24（esi+24h 直读），误按「节点+0x14+0x24」；
 *     ④ 数据(+4C 等)：相对节点，误加 +0x14 间接。
 *   结构定稿：内层条目 = 树节点本体（value 内嵌，+0x24 flag &3==1、
 *   +0x3C 百分比、+0x40 固定、+0x4C 归因 id=case 2/9/12/16 表达式构造处）；
 *   外层 value(+0x14) = 内层头节点指针。对照字段 src 改读节点+0x18
 *   （48A300 value+0x04 写点，映射关系待验证）。
 *   计数器撞位修正：0x40/0x48 是 META 区 SEQ_TOTAL/OLDEST（快照
 *   key_ev==SEQ_TOTAL 实锤），KEV→0x5C、KMULTI→0x60；diag_ver 5→6。
 *   快照附带结论：ai==0 事件 ty=0x80（键 8），不在预设 DOT 位
 *   （0x20|0x100000|0x200000）内——ty 位认知待修正；55 个周期 tick
 *   （gf 间隔 15、d=101 恒定）= 典型 DOT。
 *
 * v10.41（2026-11-27）：**DOT key 归因诊断版**（纯诊断，stats 载荷零变更）。
 *   背景：DOT 类伤害 node 攻击者==受击者（ai=0 分桶），真正归因 id 在
 *   受击者 +0xEC 条目表的插入 key（= sub_4CA1B0(来源) 归属 id，与 ai/ag
 *   同一引擎句柄空间，SUB_5CBBE0_DECOMPILE §12/§13）。本版只观测不写入：
 *   ai==0 且受击者存在生效条目（+0x24 &3==1，同 58A840 判定）的事件，
 *   只读遍历 MSVC map（深度 20 / 节点预算 64 双护栏）采集：
 *     key（node+0x10）、entry+0x4C（归属锚点）、entry+0x04（来源单位）。
 *   诊断计数 0x3C–0x58（diag_ver 4→5）：条目数 / 事件数 / 唯一 key 事件 /
 *   多 key 事件 / key!=+4C / key!=+04 / key 解析玩家系次数 / 打印行数。
 *   DbgView keydiag 行预算 200 行（防刷屏），样本 = 首个 distinct key
 *   经 resolve_cached 的 {ai=CardID, ag=key>>16, RTTI t}。
 *   目的：实跑验证 ① key 能否过句柄表 gen 校验 ② key 与 +4C/+04 的
 *   一致性（召唤归并可见性）③ 唯一/多 key 事件占比（写入策略输入）。
 *
 * v10.40（2026-11-27）：修复 ai/ag 仍全 0——RVA_MGR 换算错误。
 *   根因：dword_4F82980 的 VA 是 0x4F82980（7 位），RVA 应为 0x4B82980；
 *   v10.38/v10.39 误写 0xB82980（把 VA 当 0xF82980 换算，丢了高位 4），
 *   读到 .data 内另一个无关 dword → node 查找恒败（why|=16）→ ai/ag 全 0。
 *   依据：PE 头 SizeOfImage=0x4CF9000（.data RVA 0xB28000 + 0x40EFC34），
 *   VA 0x4F82980 落在 .data 内，符号有效。其余 RVA 均来自 6 位 VA，未受影响。
 *
 * v10.39（2026-11-27）：修复 v10.38 的 ai/ag 全 0——管理器全局现读。
 *   根因：dword_4F82980 是惰性创建的全局（4F0xxx 属性家族内多处
 *   `mov dword_4F82980, edi/ebx` 运行时写入，首次使用伤害属性系统时才有值），
 *   v10.38 却在 DLL init 时 safe_read32 一次缓存进 g_mgr —— 战斗未开始，
 *   恒为 0，导致 report_settle 的攻击者分支整体短路（why|=16，ai/ag 全 0）。
 *   修正：g_mgr 改为 report_settle 内每次现读（一次 safe_read32）；
 *   init 不再读；DbgView node_src 语义收窄为「node 原语序言校验通过」。
 *
 * v10.38（2026-11-26）：**单 hook 定稿**——hook1（sub_4F3FA0 ctor）整体移除，
 *   身份解析迁入 hook2（sub_5CAC50）内用 CDamageHandle* 完成，数据源与
 *   引擎自身解析链同源（SUB_5CBBE0_DECOMPILE §7/§10）：
 *     node = sub_4F4B50(dword_4F82980, handle) → 攻击者句柄 = [node+0Ch]
 *     → resolve_cached（引擎句柄表）；受击者对象 = ecx（调用点
 *     mov ecx,ebx 直传，detour 入口原样可读）。
 *   零丢弃口径不变（v10.37）：每次命中发布一条；解析失败字段写 0 + why 观测位。
 *   删除：report_ctor / hook_ctor / create_hook / g_id / g_id_ok / ident_t /
 *   no_prev / drop_count / ctor_hits（0x18/0x1C/0x20 退役恒 0）。
 *   diag_ver 3→4；flags bit0（hook1）废除；why bit16 扩为「攻击者句柄链
 *   解析失败」（node 查找失败 / node+0Ch=0 / Missile owner 读失败）。
 *   ag 现恒为真 gen（攻击者句柄 [node+0Ch]>>16 直取，不再有指针低位退化；
 *   vg 仍保留退化路径——受击者句柄走 GetHandle 只读语义）。
 *
 * v10.37（2026-11-26）：**hook2 不丢弃任何一次命中**——每次结算恰好发布一条。
 *   删除 report_settle 的两处早退：
 *     ① 无 hook1 身份（原 no_prev → return）：改为 ai/ag/vg/vi 四字段写 0
 *        后照发，no_prev 降级为质量计数；
 *     ② d==0（原 why|1 + drop → return）：改为 d 写 0 后照发，新增计数
 *        zero_d（0x38）。
 *   由此「ty_hits == published」严格成立（唯一例外是 payload 组装失败，不可达）。
 *   drop_count(0x1C) 语义收窄为「仅 hook1 语义过滤」，why_bits 降级为观测位。
 *   消费端口径随之变化：统计前必须自行过滤 d==0 与 ai==0 的条目。
 *   诊断块版本 2 → 3（0x38 重新启用为 zero_d，0x20 不再是丢弃）。
 *
 * v10.36（2026-11-26，1.4.0）：**架构定稿**——hook1 解析身份，hook2 补时间与数值。
 *   hook1（sub_4F3FA0，ctor 入口）完成全部身份解析并直传 ai/ag/vg/vi 四项，
 *   同时做完 DPS 语义过滤（受击者必须为敌方、攻击链终点必须是玩家侧）。
 *   hook2（sub_5CAC50，结算点）取用这四项，填入 gf（结算帧）、d（DCC328 实际
 *   扣血）、ty（sub_4F1E50 13 键重组）后发布。
 *   战斗模拟全程单线程，hook1 必在自己的结算之前且中间不插别的 ctor，因此
 *   hook1→hook2 用文件作用域变量直传即可，无配对、无判据、无缓存。
 *   本版删除（均为历次简化留下的空壳或死分支）：
 *     · 诊断位 0x20/0x38/0x3C/0x50–0x70/0x90–0xA0（pending、补发、直方图、
 *       回退计数、last_* 采样）；0x20 复用为 no_prev。
 *     · ctor 侧 d 回退（d 只有一个来源：DCC328，读不到即丢弃该条）。
 *     · why_bits bit2 死分支（参数为空改为在 hook1 内计数，可达）。
 *     · v10.32–v10.35 期间的解释性段落（其结论已并入上表）。
 *   保留的技术事实：sub_5CAC50 的 arg_0 是 CDamageHandle*（12 字节三元组：
 *   +0x0C 侧别 / +0x04 idA / +0x08 idB），属性值必须经 sub_4F13B0(handle,key) 取，
 *   +0x1C 不是 ty。
 *
 * v10.31（2026-11-26，1.1.0）：副 hook 换点 sub_4F18A0 → sub_5CAC50。
 *   新点入参一次可取两样：
 *   ① ty = sub_4F1E50(prop)，游戏自身的 13 键 OR 重组器（纯读无副作用），
 *      比 direct dword 读更完整。
 *   ② d  = sub_4F13B0(prop, &dword_DCC328)，HP 结算实际扣血总量。
 *   覆盖说明：sub_5CAC50 被敌方侧结算主函数 sub_5CBBE0 无条件调用（函数
 *   内部护盾为 0 只影响表现，不影响 hook 命中），但它是「结算点」而非
 *   「ctor 紧邻点」；hook1 只直传身份，同一节点多目标时会复用同一份身份。
 *
 * 1.0.0（2026-11-22）：首个正式发布版。项目层版本号（semver）与内部实现
 *   版本号（v10.x 沿革）从此并行：1.0.0 对应实现 v10.29；DbgView init 行
 *   携带 rel=1.0.0 impl=v10.29，部署取证以 DbgView 行为准。
 *
 * v10.30（2026-11-23，1.0.1）：装钩批量化 —— 先 MH_Initialize，再集中
 *   MH_CreateHook × 2 + MH_QueueEnableHook(MH_ALL_HOOKS) + MH_ApplyQueued，
 *   全线程 Freeze 从 2 次降为 1 次。动因（I-001）：原每钩一次 MH_EnableHook
 *   各自走 Freeze（挂起全部线程），两次全线程冻结落在 CEF210/D3D11 启动
 *   活跃窗口，疑似「游戏内报错」诱因；详见 docs/INCIDENT_LOG.md。
 *   新语义：
 *   ① 两 Create 之间零补丁、零生效 —— 任一 Create 失败（含 prologue 拒装）
 *      直接不 Apply，进程零足迹；
 *   ② 单 Create 成功 → 只排它一个，一次 Apply 单钩启用（保留旧降级模式）；
 *      双 Create 成功 → MH_ALL_HOOKS 同批启用，无「主生效/副未装」窗口；
 *   ③ ApplyQueued 部分失败时 QueueDisableHook(MH_ALL_HOOKS) + ApplyQueued
 *      回滚，保守回到无钩态（EnableHookLL 现实失败源仅 VirtualProtect）。
 *   SHM diag bit0/bit1（主/副 hook）自本版起同批翻转，恒同值。
 */

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "minhook/MinHook.h"

/* 项目发布版本（semver）：**单一事实来源 = 仓库根 VERSION 文件**。
 * 构建脚本 scripts\build_dll_msvc_direct.bat 读取该文件并注入
 * /DDPS_REL_VER="x.y.z"；源码内不硬编码版本号，避免"文件与代码两处真相"。
 * 非脚本构建（IDE / 手动 cl 未带宏）时显式降级为 "dev"，提示该产物非发布流程所出。
 * ⚠ 铁律：每次修改都必须如实更新 VERSION（与改动同一变更集），见 README §版本约定。 */
#ifndef DPS_REL_VER
#define DPS_REL_VER "dev"
#endif

/* ------------------------------------------------------------------ */
/* 导出转发（v10.27）：链接器转发字符串 + NT 绝对路径（mrexodia 技巧）。 */
/*   转发在 loader 导入绑定层完成，零桩代码：无自递归风险（不按名搜索， */
/*   NT 路径直达 SysWOW64）、无惰性竞态（绑定天生单次）、真身恒为 OS    */
/*   当前版本。⚠ x86 进程必须显式写 SysWOW64——NT 路径不经过 WOW64      */
/*   重定向，写 System32 会拿到 64 位 DLL 导致加载失败。                */
/*   导出接口指针语义：游戏导入的名字 → loader 沿转发链绑到真身导出，   */
/*   调用方无感知。                                                     */
/* ------------------------------------------------------------------ */

/* 转发条目（perfect-dll-proxy 形态，v10.28 采纳其生成代码的防漂移设计）：
 * ① 全部 6 个导出全转发——未来游戏更新改导入 MFPCreateMediaPlayerEx 或
 *   COM 导出时，加载期绑定不会失败（多余的转发条目零成本）；
 * ② COM 导出标 PRIVATE（不进静态导入库，防宿主误绑成 COM 服务入口）；
 * ③ MAKE_EXPORT 宏按 _WIN64 分流 System32/SysWOW64——本工程只可能是 x86，
 *   宏层是给未来误编译成 x64 的保险（NT 路径不走 WOW64 重定向，写死
 *   System32 会绑到 64 位 DLL）。
 * 注意：#pragma 指令遇换行即终止，字符串不可跨行拼接。 */
#ifdef _WIN64
#define MAKE_EXPORT(func)        "/EXPORT:" func "=\\\\.\\GLOBALROOT\\SystemRoot\\System32\\mfplay.dll." func
#define MAKE_EXPORT_PRIVATE(func) "/EXPORT:" func "=\\\\.\\GLOBALROOT\\SystemRoot\\System32\\mfplay.dll." func ",PRIVATE"
#else
#define MAKE_EXPORT(func)        "/EXPORT:" func "=\\\\.\\GLOBALROOT\\SystemRoot\\SysWOW64\\mfplay.dll." func
#define MAKE_EXPORT_PRIVATE(func) "/EXPORT:" func "=\\\\.\\GLOBALROOT\\SystemRoot\\SysWOW64\\mfplay.dll." func ",PRIVATE"
#endif
#pragma comment(linker, MAKE_EXPORT("MFPCreateMediaPlayer"))
#pragma comment(linker, MAKE_EXPORT("MFPCreateMediaPlayerEx"))
#pragma comment(linker, MAKE_EXPORT_PRIVATE("DllCanUnloadNow"))
#pragma comment(linker, MAKE_EXPORT_PRIVATE("DllGetClassObject"))
#pragma comment(linker, MAKE_EXPORT_PRIVATE("DllRegisterServer"))
#pragma comment(linker, MAKE_EXPORT_PRIVATE("DllUnregisterServer"))

/* ------------------------------------------------------------------ */
/* 配置（PRD FR-6：仅保留 DPS_ON）                                     */
/* ------------------------------------------------------------------ */

/* 主 hook：sub_4F3FA0（CDamageHandle ctor，三条节点创建路径唯一漏斗）。
 * 入口栈（PRD v1.6 FR-1）：[esp+4]=arg_0（this，不消费）/ [esp+8]=arg_4 攻击者
 * 对象 / [esp+0C]=arg_8 受击者对象 / [esp+10]=arg_C 伤害值指针（d = *arg_C，
 * objdump 4F41ED 实锤：mov 0x14(%ebp),%eax / mov (%eax),%eax / mov %eax,0x20(%esi)）。
 *
/* 副 hook（v10.31 换点；v10.38 起为唯一 hook）：sub_5CAC50（VA 0x5CAC50 /
 * RVA 0x1CAC50）——敌方侧结算主函数 sub_5CBBE0+0x4D5 的「受击表现」子步骤，
 * **无条件调用**（函数内部护盾为 0 只是早退，入口 hook 照常命中）。
 *   arg_0 = CDamageHandle*（12 字节三元组，**不是** CDamageProperty）：
 *     ty ← sub_4F1E50(handle)：13 键 OR 重组的完整 dword（纯读，无副作用）；
 *           序言不符 → ty_src=0，该字段整场省略。
 *     d  ← sub_4F13B0(handle, &dword_DCC328)：HP 结算实际扣血；
 *           0 = 本次未扣血，事件照发（d=0），消费端过滤（v10.37）。
 * prologue: push ebp / mov ebp,esp / and esp,-8 = 55 8B EC 83 E4 F8，
 * 取前 5 字节作漂移签名（MinHook 自行按完整指令重定位，不要求对齐）。 */
#define HOOK_SETTLE_RVA       0x1CAC50
#define HOOK_SETTLE_PATCH_LEN 5
static const BYTE EXPECT_PROLOGUE_SETTLE[HOOK_SETTLE_PATCH_LEN] =
        { 0x55, 0x8B, 0xEC, 0x83, 0xE4 };

/* 属性读取原语：调用前二次校验序言，不符则该函数指针保持 NULL，绝不乱调。 */
#define RVA_GET_PROP   0xF13B0   /* sub_4F13B0(prop,key) → u32，0 = 未设置 */
#define RVA_TY_REASM   0xF1E50   /* sub_4F1E50(prop) → ty dword            */
#define RVA_KEY_D2     0x9CC328  /* dword_DCC328（VA 0xDCC328）= 伤害总量  */
static const BYTE PROLOGUE_GET_PROP[5] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };
static const BYTE PROLOGUE_TY_REASM[3] = { 0x56, 0x57, 0x68 };

/* node 查表原语（v10.38）：sub_4F4B50(mgr, handle) → CDamageProperty 节点。
 * __thiscall(ecx = dword_4F82980 管理器, 栈参 handle)；攻击者句柄 = [node+0Ch]
 * （sub_5CBBE0 自己的解析链：v11=4F4B50(a2); v12=*(v11+12)）。
 * ⚠ dword_4F82980 是**惰性创建**的全局（4F0xxx 属性家族内多处
 * `mov dword_4F82980, edi/ebx` 运行时写入，首次使用伤害属性系统时才有值）：
 * init 时必为 0 —— v10.38 曾在 init 读一次缓存，导致整场 ai/ag=0（v10.39
 * 修正为每次结算现读）。 */
#define RVA_NODE_LOOKUP 0xF4B50  /* sub_4F4B50 → node*（0 = 查无）         */
#define RVA_MGR         0x4B82980/* dword_4F82980（VA 0x4F82980−0x400000）：
                                  * 伤害属性管理器指针。⚠ v10.39 及之前误写
                                  * 0xB82980（把 VA 当 0xF82980），读到的不是
                                  * 管理器 → node 查找恒败 → ai/ag 全 0。     */
static const BYTE PROLOGUE_NODE_LOOKUP[5] = { 0x55, 0x8B, 0xEC, 0x56, 0x57 };

/* 归属反查原语（v10.43，SUB_5CBBE0_DECOMPILE §13.3/§13.11）：
 * sub_54BC00(registry, &id) __thiscall —— registry map find → CEntry+4
 * 句柄 → F4CB70/F4CB74 gen 校验 → slot+4 ident → ident+8 懒解析 →
 * 死亡位 *( *(实体+4)+0x14 ) & 0x1000 过滤 → 返回归属锚点单位对象
 * （任一层失败返 0，可当验活门）。registry 单例 = dword_4F826E8
 * （CSimulatorPlayerEntryManager，408D20 惰性构建，战斗中必已存在；
 * 54BC00 服务多种 registry，**必须选对单例**——§13.3 调用点①）。 */
#define RVA_REVERSE   0x14BC00  /* sub_54BC00                            */
#define RVA_REGMGR    0x4B826E8 /* dword_4F826E8 = VA 0x4F826E8−0x400000
                                 * （7 位 VA 换算铁律，v10.40 教训）      */
static const BYTE PROLOGUE_REVERSE[7] =
    { 0x55, 0x8B, 0xEC, 0x56, 0xFF, 0x75, 0x08 };  /* exe 0x54BC00 实读 */

/* GameFrame（dword_F51838，官方 API 注册于 sub_B1B0F0）：
 * 暂停/倍速/脚本变速全自动正确。RVA = VA 0xF51838 - 0x400000。 */
#define RVA_GFRAME    0xB51838

static DWORD       g_base    = 0;       /* 主模块基址（init 时取一次）    */
static void       *g_tram_t  = NULL;    /* 结算 hook trampoline（保留旧名） */

/* 属性读取原语：init 时按序言校验后填充，NULL = 不可用（该字段随之缺省）。 */
/* 目标函数均为 __thiscall（ecx = prop / mgr）。C 模式不支持 __thiscall 函数
 * 指针，用 __fastcall 等价映射：第 1 参 → ecx、第 2 参 → edx、其余入栈。 */
typedef DWORD (__fastcall *fn_get_prop)(void *prop, void *unused_edx,
                                        const void *key);
typedef DWORD (__fastcall *fn_ty_reasm)(void *prop, void *unused_edx);
typedef DWORD (__fastcall *fn_node_lookup)(void *mgr, void *unused_edx,
                                           DWORD handle);
typedef DWORD (__fastcall *fn_reverse)(void *reg, void *unused_edx,
                                       const DWORD *key);   /* 54BC00 */
static fn_get_prop    g_fn_get_prop = NULL;
static fn_ty_reasm    g_fn_ty_reasm = NULL;
static fn_node_lookup g_fn_lookup   = NULL;
static fn_reverse     g_fn_reverse  = NULL;  /* v10.43 归属反查       */
static int         g_rev_enable = 1;        /* DPS_REV=0 关闭反查路径    */
static int         g_dbg_print  = 0;        /* DPS_DBG=1 才开结算路径打印 */
static DWORD          g_mgr         = 0;     /* RVA_MGR 现读值（每次结算刷新，
                                                * v10.38 曾 init 读一次 → 恒 0）*/
static BOOL        g_hook_settle = FALSE;   /* hook2（唯一 hook/发布点）    */

/* ------------------------------------------------------------------ */
/* 页级可读性预检（不触发异常、不走 SEH 分发）+ VEH 探针护盾            */
/* （v11-r4 原样保留：游戏进程 SEH 链被破坏，任何 AV 走 SEH 分发即可    */
/*   触发 FAST_FAIL_INVALID_EXCEPTION_CHAIN；探针 AV 由 VEH 直接改     */
/*   Eip 返回，完全不触碰 SEH 链；非探针异常立即放行）                  */
/* ------------------------------------------------------------------ */

static int page_readable(const void *addr, int len)
{
    MEMORY_BASIC_INFORMATION mbi;
    const BYTE *first = (const BYTE *)addr;
    const BYTE *last  = first + (len > 1 ? len - 1 : 0);

    if (!VirtualQuery(first, &mbi, sizeof mbi)) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & PAGE_GUARD) return 0;
    switch (mbi.Protect & 0xFF) {
    case PAGE_NOACCESS:
    case PAGE_EXECUTE:
        return 0;
    }
    if (last != first &&
        ((UINT_PTR)first ^ (UINT_PTR)last) > 0xFFF) {   /* 跨页：末字节页另查 */
        if (!VirtualQuery(last, &mbi, sizeof mbi)) return 0;
        if (mbi.State != MEM_COMMIT) return 0;
        if (mbi.Protect & PAGE_GUARD) return 0;
        switch (mbi.Protect & 0xFF) {
        case PAGE_NOACCESS:
        case PAGE_EXECUTE:
            return 0;
        }
    }
    return 1;
}

static DWORD g_tls_probe = TLS_OUT_OF_INDEXES;   /* 探针窗口标记槽      */
static PVOID g_veh       = NULL;                 /* VEH 句柄            */

__declspec(naked) static void probe_n_body(void)
{
    __asm {
        push    esi
        push    edi
        mov     esi, [esp+12]               /* src                          */
        mov     edi, [esp+16]               /* dst                          */
        mov     ecx, [esp+20]               /* len                          */
        xor     eax, eax
pn_loop:
        mov     dl, [esi]                   /* AV 落点（VEH 接管）          */
        mov     [edi], dl
        inc     esi
        inc     edi
        dec     ecx
        jnz     pn_loop
        mov     eax, 1
        pop     edi
        pop     esi
        ret     12
    }
}

__declspec(naked) static void probe_n_fail(void)
{
    __asm {
        xor     eax, eax
        pop     edi                         /* 与 body 的 push 对称         */
        pop     esi
        ret     12
    }
}

__declspec(naked) static void probe32_body(void)
{
    __asm {
        mov     eax, [esp+4]                /* src                          */
        mov     ecx, [esp+8]                /* dst                          */
        mov     eax, [eax]                  /* AV 落点（VEH 接管）          */
        mov     [ecx], eax
        mov     eax, 1
        ret     8
    }
}

__declspec(naked) static void probe32_fail(void)
{
    __asm {
        xor     eax, eax
        ret     8
    }
}

static LONG WINAPI probe_veh(EXCEPTION_POINTERS *ep)
{
    PEXCEPTION_RECORD er  = ep->ExceptionRecord;
    PCONTEXT          ctx = ep->ContextRecord;
    DWORD eip, flag;

    /* guard page AV 一并兜住（0x80000001），普通 AV 0xC0000005 */
    if (er->ExceptionCode != 0xC0000005 &&
        er->ExceptionCode != 0x80000001)
        return EXCEPTION_CONTINUE_SEARCH;
    if (g_tls_probe == TLS_OUT_OF_INDEXES) return EXCEPTION_CONTINUE_SEARCH;

    flag = (DWORD)(UINT_PTR)TlsGetValue(g_tls_probe);
    if (!flag) return EXCEPTION_CONTINUE_SEARCH;    /* 非探针异常，放行 */

    eip = ctx->Eip;
    if (eip >= (DWORD)(UINT_PTR)probe_n_body &&
        eip <  (DWORD)(UINT_PTR)probe_n_body + 0x40) {
        ctx->Eip = (DWORD)(UINT_PTR)probe_n_fail;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (eip >= (DWORD)(UINT_PTR)probe32_body &&
        eip <  (DWORD)(UINT_PTR)probe32_body + 0x20) {
        ctx->Eip = (DWORD)(UINT_PTR)probe32_fail;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int probe_read(const void *addr, BYTE *dst, int len)
{
    int ok;
    TlsSetValue(g_tls_probe, (LPVOID)1);
    __asm {
        push    len
        push    dst
        push    addr
        call    probe_n_body
        mov     ok, eax
    }
    TlsSetValue(g_tls_probe, (LPVOID)0);
    return ok;
}

static int probe_read32(const void *addr, DWORD *dst)
{
    int ok;
    TlsSetValue(g_tls_probe, (LPVOID)1);
    __asm {
        push    dst
        push    addr
        call    probe32_body
        mov     ok, eax
    }
    TlsSetValue(g_tls_probe, (LPVOID)0);
    return ok;
}

static int safe_read32(const void *addr, DWORD *out)
{
    if (!page_readable(addr, 4)) return 0;
    return probe_read32(addr, out);
}

static int safe_readN(const void *addr, BYTE *out, int len)
{
    if (!page_readable(addr, len)) return 0;
    return probe_read(addr, out, len);
}

/* 进程内 RTTI 类名解析：obj[0]=vftable -> vftable[-1]=COL(sig==0)
 * -> COL+12=pTypeDescriptor -> TD+8=".?AV..."。逐字节 probe 读
 * （名字串可能跨页）。失败返回 0。 */
static int rtti_name(const void *obj, char *out, int cap)
{
    DWORD vt, col, sig, td, ch;
    int i;
    if (!obj || !safe_read32(obj, &vt)) return 0;
    if (vt < 0x10000) return 0;
    if (!safe_read32((const void *)(vt - 4), &col)) return 0;
    if (col < 0x10000) return 0;
    if (!safe_read32((const void *)col, &sig) || sig != 0) return 0;
    if (!safe_read32((const void *)(col + 12), &td)) return 0;
    if (td < 0x10000) return 0;
    if (!safe_read32((const void *)(td + 4), &ch)) return 0;
    if (ch != 0) return 0;
    for (i = 0; i < cap - 1; i++) {
        if (!safe_readN((const void *)(UINT_PTR)(td + 8 + i),
                        (BYTE *)&out[i], 1))
            break;
        if (!out[i]) break;
    }
    out[i] = '\0';
    return (out[0] == '.') ? 1 : 0;     /* ".?AV..." 才可信 */
}

/* ------------------------------------------------------------------ */
/* RTTI 类名 → 紧凑类型枚举（PRD FR-3，仅 DLL 内部过滤用，不进输出）    */
/*   取 <Name> 尾精确匹配（防前缀误伤，如 CPlayerUnit@CReactorObject）  */
/* ------------------------------------------------------------------ */

static int name_tail(const char *n, const char *s)
{
    size_t ln = strlen(n), ls = strlen(s);
    return ln >= ls && memcmp(n + ln - ls, s, ls) == 0;
}

static DWORD classify_rtti(const char *n)
{
    if (name_tail(n, "PlayerApproachUnit@@"))   return 3;
    if (name_tail(n, "PlayerRemoteUnit@@"))     return 4;
    if (name_tail(n, "PlayerFoundationUnit@@")) return 5;
    if (name_tail(n, "PlayerUnit@@"))           return 6;   /* 基类兜底 */
    if (name_tail(n, "Missile@@"))              return 2;
    if (name_tail(n, "Enemy@@"))                return 1;
    return 0;   /* 未知 / 解析失败 → 丢弃（无法确认攻防双方身份） */
}

/* ------------------------------------------------------------------ */
/* CMnObjHandle 解析（逆向自 sub_42DF80，battle8 实锤）                 */
/*   handle = (gen<<16)|idx；全局表: [base+0xB4CB70]=表基址(堆指针)     */
/*   [base+0xB4CB74]=步长；entry+0=当前 gen(word)，entry+4=对象指针     */
/*   对象+8 非零时为代理指针，需再解一层（sub_42DF80 的行为）           */
/* ------------------------------------------------------------------ */
#define RVA_HBASE    0xB4CB70
#define RVA_HSTRIDE  0xB4CB74

static void *resolve_handle(DWORD handle)
{
    WORD  idx = (WORD)(handle & 0xFFFF);
    WORD  gen = (WORD)(handle >> 16);
    DWORD tblBase = 0, stride = 0, obj = 0, redirect = 0;

    if (!handle) return NULL;
    if (!safe_read32((const BYTE *)(UINT_PTR)g_base + RVA_HBASE, &tblBase) ||
        tblBase < 0x10000)
        return NULL;
    if (!safe_read32((const BYTE *)(UINT_PTR)g_base + RVA_HSTRIDE, &stride))
        return NULL;
    if (stride < 4 || stride > 0x1000) return NULL;

    {
        BYTE *entry = (BYTE *)(UINT_PTR)tblBase + (DWORD)idx * stride;
        DWORD g0 = 0;
        if (!safe_read32(entry, &g0) || (WORD)g0 != gen) return NULL;
        if (!safe_read32(entry + 4, &obj) || obj < 0x10000) return NULL;
        if (safe_read32((const BYTE *)(UINT_PTR)obj + 8, &redirect) &&
            redirect >= 0x10000)
            obj = redirect;
    }
    return (void *)(UINT_PTR)obj;
}

/* v10.43：与 resolve_handle 同一张表，但**不做 [obj+8] 代理重定向**。
 * ident 对象的 +8 正是「目标实体」懒解析槽（§13.11）——重定向会把
 * ident/实体两种身份混在一个返回值里，归属反查需要原始 ident。
 * 返回 slot+4（ident），gen 校验失败 / 槽空 → NULL。 */
static void *resolve_ident(DWORD handle)
{
    WORD  idx = (WORD)(handle & 0xFFFF);
    WORD  gen = (WORD)(handle >> 16);
    DWORD tblBase = 0, stride = 0, obj = 0;

    if (!handle) return NULL;
    if (!safe_read32((const BYTE *)(UINT_PTR)g_base + RVA_HBASE, &tblBase) ||
        tblBase < 0x10000)
        return NULL;
    if (!safe_read32((const BYTE *)(UINT_PTR)g_base + RVA_HSTRIDE, &stride))
        return NULL;
    if (stride < 4 || stride > 0x1000) return NULL;
    {
        BYTE *entry = (BYTE *)(UINT_PTR)tblBase + (DWORD)idx * stride;
        DWORD g0 = 0;
        if (!safe_read32(entry, &g0) || (WORD)g0 != gen) return NULL;
        if (!safe_read32(entry + 4, &obj) || obj < 0x10000) return NULL;
    }
    return (void *)(UINT_PTR)obj;
}

/* GetHandle（sub_AAEFC0 语义，objdump 实锤）：
 *   p1 = [obj+04h] → p2 = [p1+34h] → 句柄 = [p2+0Ch]
 * ⚠ 引擎实现是**惰性创建**：p2+0Ch 为 0 时 `call [dword_F4CB5C]` 现场建句柄回写。
 *   本函数是只读的，读不到就返回 0 —— 因此**调用时机必须在对象创建之后**
 *   （结算点 report_settle 恒满足）。
 * 逐级 safe_read，任何一级失效 → 返回 0。 */
static int get_handle(void *obj, DWORD *h_out)
{
    DWORD p1 = 0, p2 = 0;
    *h_out = 0;
    if (!obj) return 0;
    if (!safe_read32((const BYTE *)obj + 4, &p1) || p1 < 0x10000) return 0;
    if (!safe_read32((const BYTE *)(UINT_PTR)p1 + 0x34, &p2) || p2 < 0x10000)
        return 0;
    return safe_read32((const BYTE *)(UINT_PTR)p2 + 0x0C, h_out);
}

/* ------------------------------------------------------------------ */
/* 解析缓存（PRD FR-5）：1024 槽直接映射哈希 + 线性探测                 */
/*   句柄含 gen → 值唯一不复用 → 缓存永久有效，无失效逻辑。             */
/*   缓存只存解析结果不持引用：对象随时可能被引擎释放，objPtr 每次      */
/*   使用仍经 safe_read（+0x44/+0x48 读取全走 safe_read32）。           */
/*   RTTI 字符串比对只在 miss 时执行一次；单查表线程内读写，免锁。      */
/* ------------------------------------------------------------------ */
#define CACHE_SLOTS 1024

typedef struct {
    DWORD handle;       /* 打包句柄（键，含 gen）   */
    DWORD type;         /* 类型枚举（FR-3）         */
    void *obj;          /* 解析出的对象指针         */
    DWORD card;         /* CardID（玩家侧才有意义） */
} rescache_t;

static rescache_t g_rc[CACHE_SLOTS];

/* 句柄 → {类型枚举, 对象指针, CardID}。失败类型枚举 = 0。 */
static DWORD resolve_cached(DWORD handle, void **obj_out, DWORD *card_out)
{
    DWORD idx = handle & (CACHE_SLOTS - 1);
    int   i;

    *obj_out  = NULL;
    *card_out = 0;
    if (!handle) return 0;

    /* 命中探测：4 槽线性探测 */
    for (i = 0; i < 4; i++) {
        rescache_t *c = &g_rc[(idx + i) & (CACHE_SLOTS - 1)];
        if (c->handle == handle) {
            *obj_out  = c->obj;
            *card_out = c->card;
            return c->type;
        }
        if (c->handle == 0) break;      /* 空槽：后面必 miss */
    }

    /* miss：完整解析一次（resolve + RTTI + CardID） */
    {
        void *obj = resolve_handle(handle);
        DWORD type = 0, card = 0;
        if (obj) {
            char name[64];
            if (rtti_name(obj, name, sizeof name))
                type = classify_rtti(name);
            if (type >= 3 && type <= 6)         /* 玩家侧才读 CardID */
                safe_read32((const BYTE *)obj + 0x44, &card);
        }
        /* 插入：优先空槽；全满则踢 idx 槽（直接映射语义） */
        {
            rescache_t *c = &g_rc[idx];
            for (i = 0; i < 4; i++) {
                rescache_t *e = &g_rc[(idx + i) & (CACHE_SLOTS - 1)];
                if (e->handle == 0) { c = e; break; }
            }
            c->handle = handle;
            c->type   = type;
            c->obj    = obj;
            c->card   = card;
            *obj_out  = obj;
            *card_out = card;
            return type;
        }
    }
}

/* ------------------------------------------------------------------ */
/* 身份识别（v10.2 句柄路径优先，v10.38 迁至结算点）：直接 RTTI 回退      */
/*                                                                     */
/*   句柄路径 = 与引擎同源（get_handle → resolve_handle → RTTI）。       */
/*   GetHandle 是惰性创建：结算点调用时对象必已存在（ctor 已完成）。     */
/*   仍失败时直接对入口对象做 RTTI：受击者（ecx）就是单位对象本身，      */
/*   类名可信，只是拿不到句柄 gen（vg 退化对象指针低位）。               */
/* ------------------------------------------------------------------ */

/* 直接对象 RTTI 分类（回退路径） */
static DWORD type_of_obj(DWORD obj, void **obj_out, DWORD *card_out)
{
    char  name[64];
    void *o = (void *)(UINT_PTR)obj;
    DWORD t = 0, card = 0;

    *obj_out  = NULL;
    *card_out = 0;
    if (!o) return 0;
    if (rtti_name(o, name, sizeof name))
        t = classify_rtti(name);
    if (t >= 3 && t <= 6)               /* 玩家侧才读 CardID */
        safe_read32((const BYTE *)o + 0x44, &card);
    *obj_out  = o;
    *card_out = card;
    return t;
}

/* obj → {type, obj, card, 句柄}。fb 返回 1 表示走了直接 RTTI 回退。 */
static DWORD identify(DWORD obj, DWORD *h_out, void **obj_out,
                      DWORD *card_out, int *fb)
{
    DWORD h = 0, t = 0;

    *h_out = 0;
    if (fb) *fb = 0;
    if (!obj) return 0;

    if (get_handle((void *)(UINT_PTR)obj, &h) && h) {
        t = resolve_cached(h, obj_out, card_out);
        if (t) { *h_out = h; return t; }
    }
    if (fb) *fb = 1;
    *h_out = h;                          /* 可能为 0（无 gen 可用） */
    return type_of_obj(obj, obj_out, card_out);
}

/* 实例标识：有句柄 → 真 gen（打包句柄高 16 位）；无句柄 → 对象指针
 * 低位退化（同一场次内稳定，仅用于前端按实例分桶，语义对前端不透明）。 */
static DWORD inst_id(DWORD handle, DWORD obj)
{
    if (handle) return handle >> 16;
    return ((DWORD)(UINT_PTR)obj) & 0xFFFFu;
}


/* ------------------------------------------------------------------ */
/* SHM 传输层（PRD FR-4a，v1.5 head/body 分离布局）                     */
/*                                                                     */
/*   Local\aigis_dps，总 16MB，page-file backed 按需提交：              */
/*     0x000000  元数据区 1MB（有效字段在前 4KB，其余预留恒 0）         */
/*     0x100000  head 槽表 N=131072 槽 × 16B = 2MB                     */
/*     0x300000  body 环形区 13,631,488B                               */
/*   只由 writer 单侧写入；reader PAGE_READONLY 映射（信任边界归零）。  */
/*   两阶段发布：body 先写（seq 戳最后）-> 槽 body_off/span -> 槽 seq   */
/*   （u32 原子发布）-> seq_total++。writer 永不等待：覆旧策略，        */
/*   每次覆盖槽 s 时先推进 oldest_seq（丢失判定入口）。                 */
/* ------------------------------------------------------------------ */
#define SHM_NAME     L"Local\\aigis_dps"
#define SHM_TOTAL    0x1000000u                      /* 16MB            */
#define OFF_HEAD     0x100000u
#define OFF_BODY     0x300000u
#define BODY_SIZE    (SHM_TOTAL - OFF_BODY)          /* 13,631,488      */
#define HEAD_SLOTS   131072u
#define SHM_MAGIC    0x44505332u                     /* "DPS2"          */
#define SHM_HDR_VER  2u

/* 元数据区偏移（DWORD 序号 = 字节偏移 / 4） */
#define META_MAGIC      0x00u
#define META_EPOCH      0x04u
#define META_HEAD_SLOTS 0x08u
#define META_HDR_VER    0x0Cu
#define META_SEQ_TOTAL  0x40u
#define META_OLDEST     0x48u

/* 诊断区（reader 可忽略；写入方只有 DLL）。v10.38 起单 hook，零丢弃：
 * ty_hits == published 严格成立。旧配对期计数 0x18/0x1C/0x20
 * （ctor_hits/drop_count/no_prev）随 hook1 一并退役，恒 0、不再分配新含义。 */
#define META_DIAG_VER   0x10u   /* 诊断块版本（值见 shm_init 写入点）      */
#define META_DIAG_FLAGS 0x14u   /* bit1 hook2 bit2 shm（bit0 曾为 hook1，废） */
#define META_DIAG_TYHIT 0x24u   /* hook2 命中次数 = 发布条数              */
#define META_DIAG_TYPAIR 0x28u  /* 带 ty 的发布次数                       */
#define META_DIAG_PUB   0x2Cu   /* 实际发布条数（应恒 == ty_hits）        */
#define META_DIAG_GF    0x30u   /* 最近一次发布的 gf                      */
#define META_DIAG_WHY   0x34u   /* 观测位（不代表丢弃）：1 d==0 / 2 参数为空 /
                                 * 4 受击者非敌方 / 8 攻击者未归因到玩家系 /
                                 * 16 攻击者句柄链解析失败（node 查找失败 /
                                 *   node+0Ch=0 / Missile owner 读失败） /
                                 * 32 owner 非玩家系 /
                                 * 64 v10.43 反查已推进到实体层但未归因
                                 *   （含敌单位 / 锚点非玩家系；ident 缺失
                                 *   或 ident+8 未回填时无此位）             */
#define META_DIAG_ZEROD 0x38u   /* hook2 的 d==0 次数（仍发布，d 记 0）   */

/* v10.41/v10.42 DOT key 诊断（纯观测，不参与发布载荷）。
 * 口径：事件 = report_settle 中 ai==0 且受击者存在生效条目的一次结算；
 * 条目 = 受击者 +0xEC 外层 map → 内层 map 的树节点（条目字段相对节点，
 * 见 keydiag 块注释），生效判定 = node+0x24 &3==1（与 58A840 一致）。
 * 注意 0x40/0x48 是 META 区 SEQ_TOTAL/OLDEST，key 计数不得使用。 */
#define META_DIAG_KENT   0x3Cu   /* 遍历到的生效条目总数                   */
#define META_DIAG_KUNIQ  0x44u   /* distinct key 唯一的事件数（可归因候选）*/
#define META_DIAG_KMIS4C 0x4Cu   /* key != node+0x4C 的条目次数            */
#define META_DIAG_KMISSRC 0x50u  /* key != node+0x18 的条目次数（对照位）  */
#define META_DIAG_KRES   0x54u   /* key resolve_cached 为玩家系(3..6)次数  */
#define META_DIAG_KPRT   0x58u   /* keydiag DbgView 已打印行数（预算 200） */
#define META_DIAG_KEV    0x5Cu   /* 有生效条目的 ai==0 事件数              */
#define META_DIAG_KMULTI 0x60u   /* distinct key>1 或采样溢出的事件数      */
#define META_DIAG_REVTRY 0x64u   /* v10.43 归属反查尝试次数（why|=8 分支） */
#define META_DIAG_REVOK  0x68u   /* 反查成功归因次数（ai/ag 已回填）       */
#define META_DIAG_RPRT   0x6Cu   /* rev DbgView 已打印行数（预算 200）     */
#define META_DIAG_REVET1 0x70u   /* v10.44 阶段：ident+8 判为敌类(et==1)   */
#define META_DIAG_REVON0 0x74u   /* 阶段：et==0 但 [+0xC] 归属 id 为 0     */
#define META_DIAG_REVNRG 0x78u   /* 阶段：own!=0 但 registry 单例不可用    */
#define META_DIAG_REVA0  0x7Cu   /* 阶段：54BC00 判活反查返回 0            */
#define META_DIAG_REVANP 0x80u   /* 阶段：锚点实体非玩家系 RTTI            */
#define META_DIAG_REVAT1 0x84u   /* 阶段：resolve_cached(atk_h) 本身==1    */
#define REVERSE_PRINT_BUDGET 200u
#define KEYDIAG_PRINT_BUDGET 200u
static HANDLE         g_shm_map  = NULL;
static BYTE          *g_shm      = NULL;    /* 映射基址 = 元数据区      */
static volatile DWORD *g_meta     = NULL;
static volatile BYTE  *g_head     = NULL;
static volatile BYTE  *g_body     = NULL;
static DWORD          g_seq       = 0;       /* 下一个待发序号           */
static DWORD          g_body_off  = 0;       /* body 环写指针            */
static DWORD          g_epoch     = 0;       /* writer 重启检测          */
static void shm_init(void)
{
    HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                  0, SHM_TOTAL, SHM_NAME);
    BYTE  *view;
    if (!h) return;                      /* 异常环境 → 通道静默禁用        */
    view = (BYTE *)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, SHM_TOTAL);
    if (!view) { CloseHandle(h); return; }

    g_shm_map = h;
    g_shm     = view;
    g_meta    = (volatile DWORD *)view;
    g_head    = view + OFF_HEAD;
    g_body    = view + OFF_BODY;
    g_seq     = 0;
    g_body_off = 0;


    g_meta[META_MAGIC / 4]     = SHM_MAGIC;
    g_meta[META_EPOCH / 4]     = ++g_epoch;
    g_meta[META_HEAD_SLOTS / 4]= HEAD_SLOTS;
    g_meta[META_HDR_VER / 4]   = SHM_HDR_VER;
    g_meta[META_SEQ_TOTAL / 4] = 0;
    g_meta[META_OLDEST / 4]    = 0;
    g_meta[META_DIAG_VER / 4]  = 8;         /* v10.44：反查阶段计数     */
    g_meta[META_DIAG_FLAGS / 4]= 4;         /* bit2：SHM 就绪            */
    g_meta[META_DIAG_TYHIT / 4]= 0;
    g_meta[META_DIAG_TYPAIR/4] = 0;
    g_meta[META_DIAG_PUB / 4]  = 0;
    g_meta[META_DIAG_GF / 4]   = 0;
    g_meta[META_DIAG_WHY / 4]  = 0;
    g_meta[META_DIAG_ZEROD / 4]= 0;
    g_meta[META_DIAG_KENT / 4] = 0;
    g_meta[META_DIAG_KUNIQ/ 4] = 0;
    g_meta[META_DIAG_KMIS4C/4] = 0;
    g_meta[META_DIAG_KMISSRC/4]= 0;
    g_meta[META_DIAG_KRES / 4] = 0;
    g_meta[META_DIAG_KPRT / 4] = 0;
    g_meta[META_DIAG_KEV / 4]  = 0;
    g_meta[META_DIAG_KMULTI/4] = 0;
}

/* 单条发布：payload 为一行 JSON（不含 '\0'）。无分配、无文件 IO、
 * 无阻塞 —— 全部对齐 u32 volatile 写 + 1 次 InterlockedExchange 发布。 */
static void shm_publish(const char *payload, DWORD len)
{
    DWORD span, seq, body_off, i;
    volatile BYTE  *bp;
    volatile DWORD *slot;

    /* span = 4B seq 戳 + payload，pad 到 4 字节对齐 */
    span = (4u + len + 3u) & ~3u;

    seq = g_seq;
    body_off = g_body_off;
    if (body_off + span > BODY_SIZE)
        body_off = 0;                    /* 回卷：直接跳回 body 首，免哨兵 */

    /* 覆盖推进 oldest_seq（先声明收缩，reader 据此重同步）。
     * u32 回绕安全：比较/相减全部无符号（实际场次规模下不会回绕）。 */
    if (seq >= HEAD_SLOTS)
        g_meta[META_OLDEST / 4] = seq - HEAD_SLOTS + 1;

    /* ① body：payload 先写，seq 戳最后写（reader 校验 ABA 的依据） */
    bp = g_body + body_off;
    for (i = 0; i < len; i++)        bp[4 + i] = (BYTE)payload[i];
    for (; i < span - 4u; i++)       bp[4 + i] = 0;      /* pad 恒 0 */
    *(volatile DWORD *)(bp) = seq;

    /* ② head 槽寻址字段（此刻槽.seq 仍为旧值，reader 不会消费本条） */
    slot = (volatile DWORD *)(g_head + (seq % HEAD_SLOTS) * 16u);
    slot[0] = body_off;
    slot[1] = span;

    /* ③ 单一发布点：u32 原子写 = release store（x86 xchg 全屏障） */
    InterlockedExchange((volatile LONG *)&slot[2], (LONG)seq);

    /* ④ 元数据区 seq_total++（发布槽后递增） */
    g_body_off = body_off + span;
    g_seq = seq + 1;
    g_meta[META_SEQ_TOTAL / 4] = g_seq;
}

/* ------------------------------------------------------------------ */
/* 身份解析（v10.38 单 hook）：全部在结算点（report_settle）内完成。     */
/*   攻击者：node = sub_4F4B50(mgr, handle) → [node+0Ch] 句柄            */
/*           → resolve_cached（引擎句柄表 + RTTI 分类）。                */
/*   受击者：对象 = ecx（调用点 mov ecx,ebx 直传），句柄走 GetHandle     */
/*           只读语义（AAEFC0），失败退化对象指针低位。                  */
/*   无配对、无缓存身份、无跨事件状态。                                  */
/* ------------------------------------------------------------------ */

/* 诊断计数器（写入方独占，reader 只读；失败静默） */
static void diag_inc(DWORD off)
{
    if (g_meta) InterlockedIncrement((volatile LONG *)&g_meta[off / 4]);
}

static void diag_or(DWORD off, LONG bits)
{
    if (g_meta) InterlockedOr((volatile LONG *)&g_meta[off / 4], bits);
}

/* ------------------------------------------------------------------ */
/* v10.42 DOT key 诊断（修正 v10.41 的四处结构偏差）：                   */
/*   受击者 +0xEC 条目表只读遍历。汇编实锤（sub_58A840 + sub_4077C0）：  */
/*     MSVC map 节点：+0 _Left / +4 _Parent / +8 _Right /                */
/*     +0xD _Isnil(byte) / +0x10 key / +0x14 value；                     */
/*     root = head->_Parent（4077C0 从 head->_Parent 起二分）。          */
/*   外层 map 对象在 vic+0xEC：key=效果类型(+0x10)，                     */
/*     value(+0x14) = 内层头节点指针（58A840 v7=v6[5], v8=*v7）。        */
/*   内层节点 = 条目本体（数据相对节点，58A840 esi 直读实锤）：          */
/*     +0x24 生效标志(&3==1)、+0x3C 百分比、+0x40 固定值、               */
/*     +0x4C 归因 id（case 2/9/12/16 构造 CAigisExpression 处）。        */
/*   v10.41 偏差：root 取了 _Left、_Isnil 查了 +0xC、flag/+4C 多加了     */
/*   +0x14 间接——导致 key_ent 恒 0。计数器 0x40/0x48 与 META 区          */
/*   SEQ_TOTAL/OLDEST 撞位 → KEV/KMULTI 迁至 0x5C/0x60，diag_ver 5→6。   */
/* ------------------------------------------------------------------ */

typedef void (*fn_map_visit)(DWORD key, DWORD node, void *ctx);

/* 中序遍历单节点（递归，深度 20 / 预算递减双护栏，全部 safe_read32） */
static void map_walk_node(DWORD node, fn_map_visit fn, void *ctx,
                          int depth, int *budget)
{
    DWORD l, r, nil, key;
    if (!node || depth > 20 || *budget <= 0) return;
    if (!safe_read32((const BYTE *)(UINT_PTR)node, &l)) return;
    map_walk_node(l, fn, ctx, depth + 1, budget);
    if (*budget <= 0) return;
    if (!safe_read32((const BYTE *)(UINT_PTR)node + 0xC, &nil)
        || ((nil >> 8) & 0xFFu))         /* _Isnil @ +0xD（byte1）       */
        return;
    if (!safe_read32((const BYTE *)(UINT_PTR)node + 0x10, &key))
        return;
    (*budget)--;
    fn(key, node, ctx);
    if (!safe_read32((const BYTE *)(UINT_PTR)node + 8, &r)) return;
    map_walk_node(r, fn, ctx, depth + 1, budget);
}

/* map 容器（首字段 = _Myhead）：root = head->_Parent */
static void map_walk(DWORD map_base, fn_map_visit fn, void *ctx, int budget)
{
    DWORD head, root;
    if (!map_base || budget <= 0) return;
    if (!safe_read32((const BYTE *)(UINT_PTR)map_base, &head) || !head)
        return;
    if (!safe_read32((const BYTE *)(UINT_PTR)head + 4, &root)) return;
    map_walk_node(root, fn, ctx, 0, &budget);
}

/* 内层：已持有头节点指针（= 外层 node+0x14 的值），不再解引用一次 */
static void map_walk_head(DWORD head, fn_map_visit fn, void *ctx, int budget)
{
    DWORD root;
    if (!head || budget <= 0) return;
    if (!safe_read32((const BYTE *)(UINT_PTR)head + 4, &root)) return;
    map_walk_node(root, fn, ctx, 0, &budget);
}

struct keydiag_ctx {
    DWORD cur_outer;                    /* 外层 key（效果类型）         */
    DWORD keys[8];                      /* distinct 生效 key 采样 ≤8    */
    int   nkeys;
    int   nent;                         /* 生效条目总数                 */
    int   m_4c, m_src;                  /* key!=+4C / key!=+18h 计数    */
    DWORD last_key, last_4c, last_src, last_outer;
};

static void keydiag_visit_inner(DWORD key, DWORD node, void *ctxp)
{
    struct keydiag_ctx *k = (struct keydiag_ctx *)ctxp;
    DWORD flag = 0, f4c = 0, src = 0;
    int  i;
    if (!safe_read32((const BYTE *)(UINT_PTR)node + 0x24, &flag)) return;
    if ((flag & 3u) != 1u) return;       /* 生效过滤，同 58A840          */
    k->nent++;
    diag_inc(META_DIAG_KENT);
    safe_read32((const BYTE *)(UINT_PTR)node + 0x4C, &f4c);
    safe_read32((const BYTE *)(UINT_PTR)node + 0x18, &src); /* 对照位   */
    if (f4c != key) { k->m_4c++;  diag_inc(META_DIAG_KMIS4C);  }
    if (src != key) { k->m_src++; diag_inc(META_DIAG_KMISSRC); }
    for (i = 0; i < k->nkeys; i++)
        if (k->keys[i] == key) break;
    if (i == k->nkeys && k->nkeys < 8) k->keys[k->nkeys++] = key;
    k->last_key = key; k->last_4c = f4c; k->last_src = src;
    k->last_outer = k->cur_outer;
}

static void keydiag_visit_outer(DWORD key, DWORD val, void *ctxp)
{
    struct keydiag_ctx *k = (struct keydiag_ctx *)ctxp;
    k->cur_outer = key;
    map_walk_head(val, keydiag_visit_inner, ctxp, 64);
}

/* 单条发布：has_ty 决定是否输出 ty 字段（缺省不输出）。
 * 载荷组装见下（v10.29：单一模板 + 语义顺序）。 */
/* 载荷组装（v10.29：单一模板 + 语义顺序）。
 * 顺序契约（勿随意调整，变更属协议变更）：gf → ai,ag（攻击者）→ vg,vi
 * （受击方）→ d（伤害）→ ty（可选结算标志，恒在末位）。理由：
 *   ① 语义分组：时间 → 主体（攻→受）→ 结果数值 → 修饰标志；
 *   ② 可选字段固定末位 → 带/不带 ty 的事件共享稳定前缀，字节级 diff、
 *      前缀比对、未来定长二进制化均友好；
 *   ③ 单点组装：原双模板（带/不带 ty 各一份）已合并，增删字段只改这一处，
 *      杜绝"两份模板不同步"的协议漂移。 */
static void publish_event(DWORD gf, DWORD d, DWORD ai, DWORD ag, DWORD vg,
                          DWORD vi, DWORD has_ty, DWORD ty)
{
    char  payload[160];
    char *w    = payload;
    int   left = (int)sizeof payload;
    int   n;

    if (!g_shm) return;

    /* 段 1：固定六字段（时间 + 主体对 + 伤害） */
    n = _snprintf(w, left, "{\"gf\":%lu,\"ai\":%lu,\"ag\":%lu,\"vg\":%lu,"
                           "\"vi\":%lu,\"d\":%lu",
                  (unsigned long)gf, (unsigned long)ai, (unsigned long)ag,
                  (unsigned long)vg, (unsigned long)vi, (unsigned long)d);
    if (n <= 0 || n >= left) return;     /* 截断/负值：不发布半截数据 */
    w += n; left -= n;

    /* 段 2：可选 ty（末位，保证前缀稳定） */
    if (has_ty) {
        n = _snprintf(w, left, ",\"ty\":%lu", (unsigned long)ty);
        if (n <= 0 || n >= left) return;
        w += n; left -= n;
    }

    /* 段 3：闭合 */
    if (left < 2) return;
    *w++ = '}';
    *w   = '\0';

    /* 上界 = 7 字段全取 u32 满值（~114B）；超 148B 只可能是格式化异常 */
    if ((DWORD)(w - payload) > 148u) return;
    shm_publish(payload, (DWORD)(w - payload));
    diag_inc(META_DIAG_PUB);
}

/* ------------------------------------------------------------------ */
/* report_settle（hook2，v10.38 起唯一 hook）：每次命中都发布一条（v10.37）。 */
/*   [esp+4] = CDamageHandle*；ecx = 受击单位（调用点 mov ecx,ebx 直传， */
/*   detour 入口原样可读）。身份解析在本函数内完成（见上节），零丢弃口径  */
/*   不变：解析失败字段写 0 + why 观测位，d==0 写 0，一律照发。           */
/* ------------------------------------------------------------------ */

static void report_settle(const void *handle, DWORD vic_obj)
{
    DWORD ty = 0, d = 0, gf = 0, has_ty = 0;
    DWORD ai = 0, ag = 0, vg = 0, vi = 0;
    LONG  why = 0;

    diag_inc(META_DIAG_TYHIT);           /* 诊断：hook2 命中（= 发布条数） */

    /* ---------- 身份：受击者（vic_obj = ecx） ---------- */
    if (!vic_obj) {
        why |= 2;
    } else {
        DWORD vic_h = 0, vt, vcard = 0;
        void *vobj = NULL;
        vt = identify(vic_obj, &vic_h, &vobj, &vcard, NULL);
        if (vt != 1) {
            why |= 4;                    /* 受击者非敌方：身份字段保持 0  */
        } else {
            /* 受击方实例 gen：经 vt==1 过滤后必为 Enemy，恒有值 */
            vg = inst_id(vic_h, vic_obj);
            /* 受击方种类键 vi：模式槽索引 = (pval − 0x200000) >> 4。
             * pval = *( *(vobj+4) + 5Ch )，落 .text 0x201250–0x2129E0
             * 模式代码区、16 字节对齐，右移 4 即槽号（与实机点阵逐一
             * 对照验证无误）。越界/不可读时置 0（前端单列一桶）。 */
            {
                DWORD param = 0, pval = 0;
                if (vobj && safe_read32((const BYTE *)vobj + 4, &param)
                    && param >= 0x10000) {
                    safe_read32((const BYTE *)(UINT_PTR)param + 0x5C, &pval);
                    if (pval >= 0x200000u && pval < 0x400000u)
                        vi = (pval - 0x200000u) >> 4;
                }
            }
        }
    }

    /* ---------- 身份：攻击者（handle → node → [node+0Ch] 句柄） ---------- */
    /* 管理器指针每次现读：dword_4F82980 惰性创建（4F0xxx 家族运行时写入），
     * init 时必为 0 —— v10.39 修正，否则整场 ai/ag=0。 */
    if (!handle) {
        why |= 2;                        /* arg_0 为空：ty/d 也取不到     */
    } else if (g_fn_lookup &&
               safe_read32((const BYTE *)(UINT_PTR)g_base + RVA_MGR, &g_mgr) &&
               g_mgr) {
        DWORD node = g_fn_lookup((void *)(UINT_PTR)g_mgr, NULL,
                                 (DWORD)(UINT_PTR)handle);
        DWORD atk_h = 0;
        if (node)                        /* 攻击者句柄 = [node+0Ch]        */
            safe_read32((const BYTE *)(UINT_PTR)node + 0xC, &atk_h);
        if (!atk_h) {
            why |= 16;                   /* node 查无 / 句柄为 0           */
        } else {
            void *aobj = NULL;
            DWORD acard = 0;
            DWORD at = resolve_cached(atk_h, &aobj, &acard);
            if (at == 2) {
                /* Missile：owner 句柄 = [Missile+0x48]（ctor sub_442C40
                 * 实锤），导弹创建时即存在，与惰性缓存无关。 */
                DWORD ow_h = 0, ot, ocard = 0;
                void *oobj = NULL;
                if (!aobj || !safe_read32((const BYTE *)aobj + 0x48, &ow_h)
                    || !ow_h) {
                    why |= 16;
                } else {
                    ot = resolve_cached(ow_h, &oobj, &ocard);
                    if (ot < 3 || ot > 6) {
                        why |= 32;       /* owner 非玩家系                 */
                    } else {
                        ag = ow_h >> 16; /* owner 的真 gen                 */
                        ai = ocard;
                    }
                }
            } else if (at >= 3 && at <= 6) {
                ag = atk_h >> 16;        /* 句柄直取，恒真 gen             */
                ai = acard;
            } else {
                /* ---- v10.43/44 能力实例归属反查（§13.11 全链，候选 A）----
                 * node+0xC = 攻击者引擎句柄（构造期快照，恒非 0）；
                 * 未归类为 Missile/玩家系 → 本体是能力实例或敌单位。
                 * 链：atk_h → ident(slot+4) → ident+8 = attacker 实体 →
                 *   RTTI 3..6（单位，防御性直取）→ ai=[obj+0x44],
                 *   ag=get_handle>>16；
                 *   RTTI 未知（能力实例）→ [实例+0xC] 归属 id
                 *   （5687C0 注册时写入）→ 54BC00(4F826E8,&id) 判活反查
                 *   → 锚点单位 → ai=[锚点+0x44]、ag=锚点句柄>>16。
                 * ⚠ v10.43 实跑裁决（shm_20261127_103211）：ty=128（52F900
                 *   LABEL_41）路径 284/284 次 ident+8 判为 Enemy@@（et==1）
                 *   —— 该路径 node+0xC 的 ident+8 不是能力实例（疑似自节点
                 *   /受击者句柄），反查链只适用于 5AA520 能力 DOT 路径候选；
                 *   ty=128 的归因须走受击者 +0xEC key 表（keydiag 线）。
                 *   et==1 维持 ai=0（REV_ET1 计数），54BC00 不执行。
                 * DPS_REV=0 可整体关闭本分支（崩溃 A/B 分割）。 */
                DWORD rev_ok = 0, r_et = 0, r_anc = 0;
                void *r_ident = NULL, *r_ent = NULL;
                DWORD r_e8 = 0, r_own = 0;

                {
                    void *d_obj = NULL;          /* resolve_cached 出参不容
                                                    NULL——哑变量接住（命中
                                                    缓存，无额外开销）      */
                    DWORD d_card = 0;
                    if (resolve_cached(atk_h, &d_obj, &d_card) == 1)
                        diag_inc(META_DIAG_REVAT1);   /* 攻击者句柄=敌类 */
                }
                diag_inc(META_DIAG_REVTRY);
                if (g_rev_enable) {
                    r_ident = resolve_ident(atk_h);
                    if (r_ident &&
                        safe_read32((const BYTE *)r_ident + 8, &r_e8) &&
                        r_e8 >= 0x10000)
                        r_ent = (void *)(UINT_PTR)r_e8;   /* 懒解析槽     */
                    if (r_ent) {
                        DWORD ecard = 0, eh = 0;
                        void *eo = NULL;
                        r_et = type_of_obj((DWORD)(UINT_PTR)r_ent, &eo,
                                           &ecard);
                        if (r_et >= 3 && r_et <= 6) {
                            ai = ecard;               /* 单位本体直取   */
                            if (get_handle(r_ent, &eh) && eh) ag = eh >> 16;
                            rev_ok = 1;
                        } else if (r_et == 0) {       /* 能力实例候选   */
                            DWORD reg = 0;
                            if (!safe_read32((const BYTE *)r_ent + 0xC,
                                             &r_own) || !r_own) {
                                diag_inc(META_DIAG_REVON0);
                            } else if (!g_fn_reverse ||
                                       !safe_read32(
                                           (const BYTE *)(UINT_PTR)g_base
                                           + RVA_REGMGR, &reg) || !reg) {
                                diag_inc(META_DIAG_REVNRG);
                            } else if (!(r_anc = g_fn_reverse(
                                             (void *)(UINT_PTR)reg,
                                             NULL, &r_own))) {
                                diag_inc(META_DIAG_REVA0);
                            } else {
                                DWORD ac2 = 0, ah = 0, at2;
                                void *ao2 = NULL;
                                at2 = type_of_obj(r_anc, &ao2, &ac2);
                                if (at2 >= 3 && at2 <= 6) {
                                    ai = ac2;
                                    if (get_handle((void *)(UINT_PTR)r_anc,
                                                   &ah) && ah)
                                        ag = ah >> 16;
                                    rev_ok = 1;
                                } else {
                                    diag_inc(META_DIAG_REVANP);
                                }
                            }
                        } else if (r_et == 1) {
                            diag_inc(META_DIAG_REVET1);
                        }
                        /* 其余 et：维持 ai=0，why|=8 旧行为 */
                    }
                }
                if (rev_ok) {
                    diag_inc(META_DIAG_REVOK);
                } else {
                    why |= 8;             /* 未归因（与 v10.42 相同位）    */
                    if (r_ent)
                        why |= 64;        /* 反查已执行但 ident+8 链上
                                             未归因（细分观测）            */
                }
                /* DbgView rev 样本行：预算 200 行。
                 * ⚠ v10.44 起默认关闭（DPS_DBG=1 才开）：结算路径内 ODS 的
                 * DBG_PRINTEXCEPTION_C 走 SEH 分发，游戏 SEH 链损坏环境下
                 * 实测触发 fail-fast 0xC0000409（dump 实锤在途记录）。 */
                if (g_dbg_print && g_meta
                    && g_meta[META_DIAG_RPRT / 4] < REVERSE_PRINT_BUDGET) {
                    char msg[224];
                    diag_inc(META_DIAG_RPRT);
                    _snprintf(msg, sizeof msg - 1,
                        "[dps] rev atk_h=%lX idt=%lX ent=%lX "
                        "et=%lu own=%lX anc=%lX ai=%lu ag=%lu ok=%d",
                        (unsigned long)atk_h,
                        (unsigned long)(UINT_PTR)r_ident,
                        (unsigned long)(UINT_PTR)r_ent,
                        (unsigned long)r_et,
                        (unsigned long)r_own,
                        (unsigned long)r_anc,
                        (unsigned long)ai, (unsigned long)ag,
                        (int)rev_ok);
                    msg[sizeof msg - 1] = '\0';
                    OutputDebugStringA(msg);
                }
            }
        }
    } else {
        why |= 16;                       /* node 原语不可用：攻击者未知    */
    }

    /* ty：游戏自身的 13 键 OR 重组器（纯读，无副作用） */
    if (handle && g_fn_ty_reasm) {
        ty = g_fn_ty_reasm((void *)handle, NULL);
        has_ty = 1;
    }

    /* d：属性表里的伤害总量（DCC328 = 伤害计算管线的最终值）。
     * v10.37 起取不到 / 为 0 也照常发布（d 记 0），不再整条丢弃。        */
    if (handle && g_fn_get_prop)
        d = g_fn_get_prop((void *)handle, NULL,
                          (const void *)((const BYTE *)(UINT_PTR)g_base
                                         + RVA_KEY_D2));
    if (!d) {
        diag_or(META_DIAG_WHY, 1);
        diag_inc(META_DIAG_ZEROD);       /* 质量计数，不是丢弃             */
    }

    /* gf：结算这一帧的 GameFrame（时间轴随发布时刻） */
    safe_read32((const BYTE *)(UINT_PTR)g_base + RVA_GFRAME, &gf);
    if (g_meta) g_meta[META_DIAG_GF / 4] = gf;

    /* ---------- v10.41 DOT key 诊断（纯观测，不改发布字段） ---------- */
    /* 触发：ai==0（DOT 自节点 / 攻击者未归因到玩家系）且受击者对象在手。 */
    if (!ai && vic_obj) {
        static struct keydiag_ctx kd;
        void  *kd_obj = NULL;
        DWORD kd_card = 0, kd_t;
        kd.nent = 0; kd.nkeys = 0;
        kd.m_4c = 0; kd.m_src = 0;
        kd.last_key = 0; kd.last_4c = 0; kd.last_src = 0;
        kd.last_outer = 0; kd.cur_outer = 0;
        map_walk((DWORD)(UINT_PTR)vic_obj + 0xEC,
                 keydiag_visit_outer, &kd, 32);
        if (kd.nent) {
            diag_inc(META_DIAG_KEV);
            if (kd.nkeys == 1)     diag_inc(META_DIAG_KUNIQ);
            else if (kd.nkeys > 1) diag_inc(META_DIAG_KMULTI);
            kd_t = resolve_cached(kd.keys[0], &kd_obj, &kd_card);
            if (kd_t >= 3 && kd_t <= 6) diag_inc(META_DIAG_KRES);
            /* DbgView 样本行：预算 200 行（防刷屏），读 meta 计数。
             * v10.44 起默认关闭（DPS_DBG=1 才开）——同 rev 行理由。 */
            if (g_dbg_print && g_meta
                && g_meta[META_DIAG_KPRT / 4] < KEYDIAG_PRINT_BUDGET) {
                char msg[224];
                diag_inc(META_DIAG_KPRT);
                _snprintf(msg, sizeof msg - 1,
                    "[dps] keydiag gf=%lu ty=%lX t=%lu ent=%d nkey=%d "
                    "k=%lX ai=%lu ag=%lu +4C=%lX src=%lX o=%lX "
                    "m4c=%d msrc=%d",
                    (unsigned long)gf, (unsigned long)ty, (unsigned long)kd_t,
                    kd.nent, kd.nkeys,
                    (unsigned long)kd.keys[0],
                    (unsigned long)kd_card,          /* ai 候选 = CardID */
                    (unsigned long)(kd.keys[0] >> 16), /* ag 候选 = gen */
                    (unsigned long)kd.last_4c,
                    (unsigned long)kd.last_src,
                    (unsigned long)kd.last_outer,
                    kd.m_4c, kd.m_src);
                msg[sizeof msg - 1] = '\0';
                OutputDebugStringA(msg);
            }
        }
    }

    if (why) diag_or(META_DIAG_WHY, why);
    if (has_ty) diag_inc(META_DIAG_TYPAIR);
    publish_event(gf, d, ai, ag, vg, vi, has_ty, ty);
}

__declspec(naked) static void hook_settle(void)
{
    __asm {
        pushad
        mov     eax, [esp+36]           /* arg_0 = CDamageHandle*（32B+4）*/
        mov     edx, [esp+24]           /* pushad 存的原 ecx = 受击单位   */
        push    edx
        push    eax
        call    report_settle
        add     esp, 8
        popad
        jmp     [g_tram_t]              /* 原 5 字节序言 + 回跳          */
    }
}

/* 结算 hook 创建：同主 hook，只 Create 不 Enable。
 * hook2 是唯一发布点，Create 失败 = DPS 通道整场关闭（游戏无感知），
 * 因此 DbgView 的 settle_hook= 是唯一现场判据。 */
static BOOL create_hook_settle(void)
{
    BYTE *tgt = (BYTE *)(UINT_PTR)g_base + HOOK_SETTLE_RVA;

    if (memcmp(tgt, EXPECT_PROLOGUE_SETTLE, HOOK_SETTLE_PATCH_LEN) != 0) {
        char msg[128];
        _snprintf(msg, sizeof msg - 1,
            "[dps] prologue mismatch @ RVA 0x%X (settle hook), exe updated? "
            "hook skipped, DPS channel disabled", HOOK_SETTLE_RVA);
        OutputDebugStringA(msg);
        return FALSE;
    }
    return MH_CreateHook(tgt, (void *)hook_settle, &g_tram_t) == MH_OK;
}

/* ------------------------------------------------------------------ */
/* 批量启用（v10.30）：一次 MH_QueueEnableHook(MH_ALL_HOOKS) +
 * MH_ApplyQueued —— 仅一次 Freeze（挂起全部线程 + ProcessThreadIPs 修 EIP
 * + 写补丁 + 恢复），替代原先每钩一次 MH_EnableHook 的两次 Freeze。
 *   - ApplyQueued 部分失败（循环内首个 EnableHookLL 失败即返回，先前钩子
 *     可能已生效）：QueueDisableHook(MH_ALL_HOOKS) + ApplyQueued 全量回滚，
 *     保守回到无钩态 —— EnableHookLL 的现实失败源仅 VirtualProtect。
 * 返回 TRUE = 队列应用成功（已 Create 的钩子全部启用）；
 * 启用与否的最终裁决（g_hook_settle）由调用方按 Create 结果合并。 */
static BOOL apply_queued_enable(void)
{
    if (MH_QueueEnableHook(MH_ALL_HOOKS) != MH_OK)
        return FALSE;                    /* 记账失败：全部保持未启用 */
    if (MH_ApplyQueued() != MH_OK) {
        /* 部分应用可能存在 → 全量回滚（再一次 Freeze） */
        if (MH_QueueDisableHook(MH_ALL_HOOKS) == MH_OK)
            MH_ApplyQueued();
        return FALSE;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* 初始化线程入口（v10.26）：全部初始化逻辑挪出 DllMain。DllMain 持有   */
/* loader lock，任何可能阻塞/重入 loader 的操作都是禁区；hook 装钩（含  */
/* MinHook 的线程挂起）必须在无锁线程里做。失败路径全部静默（游戏无感知）。*/
/* ------------------------------------------------------------------ */

static DWORD WINAPI init_thread_proc(LPVOID arg)
{
    char tmp[32];
    BOOL c_settle, applied;              /* v10.38 单 hook：只剩结算钩      */

    if (GetEnvironmentVariableA("DPS_ON", tmp, sizeof tmp) &&
        lstrcmpA(tmp, "0") == 0)
        return 0;                        /* 显式禁用全部 hook 与 SHM 写入 */

    g_base = (DWORD)(UINT_PTR)GetModuleHandleA(NULL);

    /* v10.44 运行开关：
     *  DPS_REV=0 → 关闭归属反查（崩溃 A/B 分割用；why|=8 行为回到 v10.42）
     *  DPS_DBG=1 → 才允许结算路径内 OutputDebugStringA 打印（v10.43 实测
     *              在游戏的损坏 SEH 链上引发 fail-fast 0xC0000409，默认关）*/
    if (GetEnvironmentVariableA("DPS_REV", tmp, sizeof tmp) &&
        lstrcmpA(tmp, "0") == 0)
        g_rev_enable = 0;
    if (GetEnvironmentVariableA("DPS_DBG", tmp, sizeof tmp) &&
        lstrcmpA(tmp, "1") == 0)
        g_dbg_print = 1;

    /* VEH 探针护盾必须先于 hook 安装（探针 AV 永不进 SEH 链）。 */
    g_tls_probe = TlsAlloc();
    g_veh = AddVectoredExceptionHandler(1, probe_veh);

    shm_init();

    if (MH_Initialize() != MH_OK)
        goto diag;                       /* 引擎初始化失败：hook 不装 */

    /* v10.38 单 hook：Create（含序言校验，零补丁零生效）→ 单次 Queue+Apply。
     * 启用最终态 = Create 结果 ∧ Apply 结果。 */
    c_settle = create_hook_settle();
    applied  = c_settle ? apply_queued_enable() : FALSE;
    g_hook_settle = (BOOL)(c_settle && applied);

    /* 原语按序言校验后绑定：不符则保持 NULL（ty 省略 / d 取不到写 0 /
     * 攻击者身份解析失败），绝不把漂移过的地址当函数调。 */
    {
        const BYTE *hp = (const BYTE *)(UINT_PTR)g_base + RVA_GET_PROP;
        const BYTE *tp = (const BYTE *)(UINT_PTR)g_base + RVA_TY_REASM;
        const BYTE *np = (const BYTE *)(UINT_PTR)g_base + RVA_NODE_LOOKUP;
        const BYTE *rp = (const BYTE *)(UINT_PTR)g_base + RVA_REVERSE;
        if (memcmp(hp, PROLOGUE_GET_PROP, sizeof PROLOGUE_GET_PROP) == 0)
            g_fn_get_prop = (fn_get_prop)hp;
        if (memcmp(tp, PROLOGUE_TY_REASM, sizeof PROLOGUE_TY_REASM) == 0)
            g_fn_ty_reasm = (fn_ty_reasm)tp;
        if (memcmp(np, PROLOGUE_NODE_LOOKUP, sizeof PROLOGUE_NODE_LOOKUP) == 0)
            g_fn_lookup = (fn_node_lookup)np;
        if (memcmp(rp, PROLOGUE_REVERSE, sizeof PROLOGUE_REVERSE) == 0)
            g_fn_reverse = (fn_reverse)rp;   /* v10.43 归属反查（54BC00） */
        /* g_mgr 不在 init 读：dword_4F82980 惰性创建，此时必为 0。
         * 每次结算时在 report_settle 内现读（v10.39）。 */
    }

    /* 诊断：安装状态写入 SHM flags + DbgView 单行摘要（排查"无数据"用） */
    if (g_meta) {
        DWORD flags = 4u;               /* bit2 SHM 就绪                  */
        if (g_hook_settle) flags |= 2u;     /* bit1 hook2（唯一 hook）        */
        g_meta[META_DIAG_FLAGS / 4] = flags;
    }
    {
        char msg[192];
        _snprintf(msg, sizeof msg - 1,
            "[dps] init: rel=%s impl=v10.44 shm=%d settle_hook=%d(RVA 0x%X) "
            "node_src=%d ty_src=%d d_src=%d rev=%d(rev_en=%d dbg=%d) base=0x%X",
            DPS_REL_VER, g_shm ? 1 : 0, g_hook_settle, HOOK_SETTLE_RVA,
            g_fn_lookup ? 1 : 0,      /* mgr 现读，node_src 仅表原语绑定 */
            g_fn_ty_reasm ? 1 : 0, g_fn_get_prop ? 1 : 0,
            g_fn_reverse ? 1 : 0, g_rev_enable, g_dbg_print,
            (unsigned)g_base);
        OutputDebugStringA(msg);
    }
diag:
    return 0;
}

/* DllMain（v10.26 最小化）：只做线程创建。初始化全在 init_thread_proc——
 * DllMain 持 loader lock，装钩/线程挂起/任何可能阻塞的操作都必须在锁外。
 * DETACH 清空：代理 DLL 顶替在导入表里永不动态卸载，进程退出期 OS 统一
 * 回收映射/句柄/TLS；原 FreeLibrary 调用是规范明令禁止的 loader lock
 * 重入点，一并移除。 */
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(inst);
        CloseHandle(CreateThread(NULL, 0, init_thread_proc, NULL, 0, NULL));
        break;
    }
    return TRUE;
}
