/* ==========================================================================
 * aigis-dps / mfplay_proxy.c —— 正式发布版 1.1.0（PRD v1.7，实现版本 v10.31）
 *
 * 业务：主 hook（sub_4F3FA0，RVA 0xF3FA0，CDamageHandle ctor / 伤害节点诞生点）
 * 命中时从入口参数直接取得「攻击者对象 / 受击者对象 / 伤害值指针」，在 DLL 内
 * 完成 GetHandle + resolve + DPS 语义过滤，以一行 JSON 经命名共享内存环形缓冲
 * （Local\aigis_dps）转发给接收端。
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
 *     d  = 伤害值。取结算 hook 处的属性表伤害总量
 *          （sub_4F13B0(prop,&dword_DCC328) = HP 结算实际扣血）；读到 0
 *          （未设置）时退回主 hook 登记的 *arg_C 入口值。
 *          v10.32 起 d 只有这一条产出路径，不再与 ctor 口径混用。
 *     ty = 伤害结算标志集 = 结算 hook（sub_5CAC50）入参 arg_0（CDamageHandle*）
 *          → sub_4F1E50 13 键 OR 重组取得完整 dword（纯读无副作用）。
 *          位域 bit0~21：bit0=Magic、bit6=Critical、bit7=紫档基线等，
 *          详见 FINDINGS §44。
 *          v10.32：发布只发生在结算 hook，且必须消费到本次 pending，因此
 *          「事件缺 ty」只剩 ty_src=0（sub_4F1E50 序言漂移）一种成因。
 *          **可选字段恒在末位**：带/不带 ty 的事件共享稳定前缀。
 *
 * v10.2（2026-11-20 实跑修正）：身份解析从 ctor 入口推迟到副 hook（ctor 之后）。
 *   sub_AAEFC0 的句柄是惰性创建的，且在 4F4xxx 内只被 4F3FA0 自己调用——入口处
 *   导弹等一次性对象的句柄缓存必为 0，导致「少数正确、大量误过滤」。详见 pend_t。
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
 * v10.33（2026-11-26，1.2.1）：配对判据改为**受击单位对象指针相等**。
 *   旧（v10.32）：结算 hook 命中即无条件消费 pending —— 只要这次结算到来，
 *   不管它是不是 pending 记的那一次伤害，都拿 pending 的 atk/vic 发布。
 *   证据（反汇编）：sub_5CAC50 的 ecx（this）= 受击单位对象本身 —— 调用点
 *   sub_5CBBE0+0x4D5 里 ecx=ebx，而 [ebx+0Ch] 正是刚被扣减的 HP；同一对象
 *   也作为第三参传给 sub_4F35B0 构造 CDamageHandle。它与主 hook 的 arg_8 是
 *   同一个实例，因此**指针相等即同一次伤害**，可作唯一配对判据。
 *   新：指针不等 → 跳过（不消费、不发布、不补发）；相等 → 消费并发布。
 *   同时删掉「槽被挤占即旧事件作废」的记账（0x38 改为 pair_miss 计数）。
 *   注意：不是「CDamageProperty 指针」—— 两个 hook 各自面对的是不同栈帧上的
 *   CDamageHandle，property 本体从未暴露给 hook（见 docs/SHM_PROTOCOL.md）。
 *
 * v10.32（2026-11-26，1.2.0）：**发布权收敛到结算 hook 一处**。
 *   动因：v10.29–v10.31 有 4 条产出路径（结算 hook 正常 / pending 挤占补发 /
 *   槽不可用就地发布 / 结算 hook 未装），只有 1 条带 ty，其余 3 条缺 ty 且 d
 *   退回 ctor 入口口径 —— 同一份 DPS 里混着两种伤害语义，对账闭合不了。
 *   改法：主 hook（sub_4F3FA0）降级为**纯身份登记**，不做任何发布；publish
 *   只在 report_settle 里发生，且要求受击对象指针与登记一致（v10.33 收紧）。
 *   代价是失配即丢事件（PMISS / NOSLOT 计数），收益是事件 ty/d 同源、口径唯一。
 *   附带修正：v10.31 的「ty 退化直读 prop+0x1C」是错的 —— sub_5CAC50 的
 *   arg_0 是 CDamageHandle（12 字节三元组 +0x0C 侧别/+0x04 idA/+0x08 idB），
 *   不是 CDamageProperty，+0x1C 既越界也不含 ty。已删除该分支。
 *
 * v10.31（2026-11-26，1.1.0）：副 hook 换点 sub_4F18A0 → sub_5CAC50。
 *   新点入参一次可取两样：
 *   ① ty = sub_4F1E50(prop)，游戏自身的 13 键 OR 重组器（纯读无副作用），
 *      比 direct dword 读更完整。
 *   ② d  = sub_4F13B0(prop, &dword_DCC328)，HP 结算实际扣血总量；读到 0
 *      时退回 ctor 侧 *arg_C。协议布局不变，d 语义改为「结算总扣血」。
 *   覆盖说明：sub_5CAC50 被敌方侧结算主函数 sub_5CBBE0 无条件调用（函数
 *   内部护盾为 0 只影响表现，不影响 hook 命中），但它是「结算点」而非
 *   「ctor 紧邻点」，多条伤害节点并入同一次结算时 pending 会被后写覆盖。
 *   （该覆盖问题在 v10.32 由「丢弃 + 计数」处理，不再补发半成品事件。）
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
 * ⚠ prologue 实测（2026-11-20，objdump .text 0x4F3FA0）：
 *     55 8B EC 6A FF 68 55 C0 C7 00
 *   = push ebp / mov ebp,esp / push -1(6A FF 短编码) / push scopedTable
 *   PRD 早期写的 "55 8B EC 68 FF FF FF FF"（push imm32 形态）与实物不符，
 *   按 8 字节比对会第 4 字节失配 → hook 静默拒装（v9/v10 实跑无数据的根因）。
 *   取稳定 5 字节（3 条完整指令，55/8B EC/6A FF）作补丁长度，后续 68 imm32
 *   是 scopedTable 地址（随构建变化），不参与比对。 */
#define HOOK_RVA         0xF3FA0
#define HOOK_PATCH_LEN   5
static const BYTE EXPECT_PROLOGUE[HOOK_PATCH_LEN] =
        { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };

/* 副 hook（v10.31 换点）：sub_5CAC50（VA 0x5CAC50 / RVA 0x1CAC50）——
 * 敌方侧结算主函数 sub_5CBBE0+0x4D5 的「受击表现」子步骤，**无条件调用**
 * （函数内部护盾为 0 只是早退，入口 hook 照常命中）。
 *   arg_0 = CDamageProperty*（不再是 ty 指针），据此一次取两样：
 *     ty ← sub_4F1E50(prop)：13 键 OR 重组的完整 dword（纯读，无副作用）；
 *           序言不符/未解析时退化为 prop+0x1C 直读（原 4F18A0 同源缓存）。
 *     d2 ← sub_4F13B0(prop, &dword_DCC328)：HP 结算实际扣血总量；
 *           读到 0（未设置）则退回 ctor 侧 d。
 * prologue: push ebp / mov ebp,esp / and esp,-8 = 55 8B EC 83 E4 F8，
 * 取前 5 字节作漂移签名（MinHook 自行按完整指令重定位，不要求对齐）。 */
#define HOOK_SETTLE_RVA       0x1CAC50
#define HOOK_SETTLE_PATCH_LEN 5
static const BYTE EXPECT_PROLOGUE_SETTLE[HOOK_SETTLE_PATCH_LEN] =
        { 0x55, 0x8B, 0xEC, 0x83, 0xE4 };

/* 属性读取原语（v10.31）：调用前二次校验序言，不符则该项降级，绝不乱调。 */
#define RVA_GET_PROP   0xF13B0   /* sub_4F13B0(prop,key) → u32，0 = 未设置 */
#define RVA_TY_REASM   0xF1E50   /* sub_4F1E50(prop) → ty dword            */
#define RVA_KEY_D2     0x9CC328  /* dword_DCC328（VA 0xDCC328）= 伤害总量  */
static const BYTE PROLOGUE_GET_PROP[5] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };
static const BYTE PROLOGUE_TY_REASM[3] = { 0x56, 0x57, 0x68 };

/* GameFrame（dword_F51838，官方 API 注册于 sub_B1B0F0）：
 * 暂停/倍速/脚本变速全自动正确。RVA = VA 0xF51838 - 0x400000。 */
#define RVA_GFRAME    0xB51838

static DWORD       g_base    = 0;       /* 主模块基址（init 时取一次）    */
static BOOL        g_hooked  = FALSE;
static void       *g_tram    = NULL;    /* sub_4F3FA0 的 trampoline       */
static void       *g_tram_t  = NULL;    /* 副 hook trampoline（保留旧名） */

/* 属性读取原语（v10.31）：init 时按序言校验后填充，NULL = 不可用 → 降级。 */
/* 目标函数均为 __thiscall（ecx = prop）。C 模式不支持 __thiscall 函数指针，
 * 用 __fastcall 等价映射：第 1 参 → ecx、第 2 参 → edx、其余入栈。 */
typedef DWORD (__fastcall *fn_get_prop)(void *prop, void *unused_edx,
                                        const void *key);
typedef DWORD (__fastcall *fn_ty_reasm)(void *prop, void *unused_edx);
static fn_get_prop g_fn_get_prop = NULL;
static fn_ty_reasm g_fn_ty_reasm = NULL;
static BOOL        g_hook_settle = FALSE;   /* 副 hook 安装状态（ty 降级开关）*/

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

/* GetHandle（sub_AAEFC0 语义，objdump 实锤）：
 *   p1 = [obj+04h] → p2 = [p1+34h] → 句柄 = [p2+0Ch]
 * ⚠ 引擎实现是**惰性创建**：p2+0Ch 为 0 时 `call [dword_F4CB5C]` 现场建句柄回写。
 *   本函数是只读的，读不到就返回 0 —— 因此**调用时机必须在 ctor 返回之后**
 *   （4F3FA0 内部会做这件事），入口处调用会漏掉所有新建对象（导弹必中）。
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
/* 身份识别（v10.2）：句柄路径优先，直接 RTTI 回退                      */
/*                                                                     */
/*   句柄路径 = 与引擎同源（get_handle → resolve_handle → RTTI），       */
/*   但依赖 GetHandle 的惰性缓存已被创建。ctor 入口处该缓存可能还是 0   */
/*   （ missiles 必为 0）——所以解析时机必须在 ctor 之后（副 hook）。     */
/*   仍失败时直接对入口对象做 RTTI：ctor 收到的就是伤害载体对象本身      */
/*   （node+0xC = GetHandle([arg_4+4])，battle10 里其 RTTI 即 Missile /  */
/*   PlayerApproachUnit），类名可信，只是拿不到句柄 gen。                */
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

/* 诊断区（可选，写入方只有 DLL；reader 可忽略。正式版可全 0）
 * 作用：定位「SHM 无数据」时报卡在哪一级：hook 未命中 / 全量过滤 /
 * ty 配对卡死 / 发布失败。字段语义见 docs/SHM_PROTOCOL.md §4.3。 */
#define META_DIAG_VER   0x10u   /* 诊断块版本 = 1                   */
#define META_DIAG_FLAGS 0x14u   /* bit0 主hook bit1 tyhook bit2 shm bit3 crchook */
#define META_DIAG_CTOR  0x18u   /* 主 hook 命中次数                 */
#define META_DIAG_DROP  0x1Cu   /* 语义过滤丢弃次数                 */
#define META_DIAG_PEND  0x20u   /* 挂入 pending 次数                */
#define META_DIAG_TYHIT 0x24u   /* 副 hook 命中次数                 */
#define META_DIAG_TYPAIR 0x28u  /* 配对成功次数（带 ty 发布）       */
#define META_DIAG_PUB   0x2Cu   /* 实际发布条数                     */
#define META_DIAG_GF    0x30u   /* 最近一次读到的 gf                */
#define META_DIAG_WHY   0x34u   /* 丢弃原因位：1 d==0 2 攻击者无法识别
                                 * 4 受击者非敌方 8 攻击者非玩家
                                 * 16 missile owner 解析失败
                                 * 32 owner 非玩家 */
#define META_DIAG_PMISS 0x38u   /* 结算受击对象 ≠ pending 记录（跳过）*/
#define META_DIAG_NOSLOT 0x3Cu  /* 主 hook 命中但无槽位 → 事件弃置   */
/* v10.2 追加：身份判定分布的直方图（定位「误过滤」用的核心证据） */
#define META_DIAG_HISTA 0x50u   /* atk 类型直方图 [0..7]（16B…共 32B） */
#define META_DIAG_HISTV 0x70u   /* vic 类型直方图 [0..7]               */
#define META_DIAG_FB    0x90u   /* 走「直接 RTTI 回退」的次数          */
#define META_DIAG_NOPD  0x94u   /* 副 hook 命中但无 pending 次数       */
#define META_DIAG_LASTA 0x98u   /* 最近一次 atk 类型                   */
#define META_DIAG_LASTV 0x9Cu   /* 最近一次 vic 类型                   */
#define META_DIAG_LASTW 0xA0u   /* 最近一次丢弃原因位                  */
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
    g_meta[META_DIAG_VER / 4]  = 1;
    g_meta[META_DIAG_FLAGS / 4]= 4;         /* bit2：SHM 就绪            */
    g_meta[META_DIAG_CTOR / 4] = 0;
    g_meta[META_DIAG_DROP / 4] = 0;
    g_meta[META_DIAG_PEND / 4] = 0;
    g_meta[META_DIAG_TYHIT / 4]= 0;
    g_meta[META_DIAG_TYPAIR/4] = 0;
    g_meta[META_DIAG_PUB / 4]  = 0;
    g_meta[META_DIAG_GF / 4]   = 0;
    g_meta[META_DIAG_WHY / 4]  = 0;
    g_meta[META_DIAG_PMISS / 4] = 0;
    {   int i;
        for (i = 0; i < 8; i++) {
            g_meta[(META_DIAG_HISTA + i * 4) / 4] = 0;
            g_meta[(META_DIAG_HISTV + i * 4) / 4] = 0;
        }
    }
    g_meta[META_DIAG_FB / 4]    = 0;
    g_meta[META_DIAG_NOPD / 4]  = 0;
    g_meta[META_DIAG_LASTA / 4] = 0;
    g_meta[META_DIAG_LASTV / 4] = 0;
    g_meta[META_DIAG_LASTW / 4] = 0;
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
/* 配对槽（v10.32 语义）：主 hook 只登记，结算 hook 独占发布权。         */
/*   主 hook 过滤通过 → 挂 per-thread pending 槽（TLS），不发布；       */
/*   结算 hook 入口 → 消费 pending，用同一 prop 取 ty/d 后发布。         */
/*   槽已被新节点覆盖 → 旧登记静默消失（不补发、不记账）；              */
/*   无槽位（结算 hook 未装 / TLS 失败）→ 事件**丢弃**并计 NOSLOT；      */
/*   结算 hook 命中但无 pending → 跳过并计 NOPD；                        */
/*   v10.33：结算的受击对象指针 ≠ 登记的 vic_obj → 跳过并计 PMISS，     */
/*   且**不消费** pending（它还在等属于自己的那次结算）。                */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* ⚠ 2026-11-20 实跑修正：身份解析必须推迟到 ctor 之后。
 *
 * GetHandle（sub_AAEFC0）是**惰性创建**语义：
 *     p  = [this+0x34]; h = [p+0xC]; if (!h) h = create(this), [p+0xC] = h;
 * 而整个 4F4xxx 区间内 call 0xaaefc0 只出现在 ctor 内部的两处（4f41d4 攻击者 /
 * 4f41e5 受击者）——即句柄是**在 ctor 里才被创建**的。在 ctor 入口（hook 点）
 * 读句柄缓存：长命单位（近战）多数已被别的系统建过，而导弹这类一次性对象的
 * 缓存必然为 0 → 攻击者解析失败 → 全部丢弃。这正是「只有少数正确条目、大量
 * 攻击被过滤」的根因（battle10 中 Missile→Enemy 占 13583 条，远程伤害全走它）。
 *
 * 对策：主 hook 只暂存入口参数（d 在入口读，终值、指针之后可能失效），身份
 * 解析挪到副 hook（v10.31 = sub_5CAC50 结算点；原先 4F18A0）：此时句柄必已由 ctor 建好。解析
 * 仍失败时再走「直接对象 RTTI」回退（不依赖句柄）。 */
typedef struct {
    DWORD gf, d;                        /* 入口读数（d = *arg_C，终值） */
    DWORD atk_obj, vic_obj;             /* 入口对象指针（arg_4/arg_8）  */
    DWORD used;                         /* pending 占用标志             */
} pend_t;
/* v10.33 配对判据 = vic_obj（受击单位对象指针）与结算侧 this 指针相等。
 * 这个指针在两个 hook 里指的是同一个对象实例，因此是**真指针比较**，不是
 * 启发式；反汇编依据见文件头 v10.33 条目。 */

static DWORD g_tls_pend = TLS_OUT_OF_INDEXES;

static pend_t *pend_get(void)
{
    pend_t *p;
    if (g_tls_pend == TLS_OUT_OF_INDEXES) return NULL;
    p = (pend_t *)TlsGetValue(g_tls_pend);
    if (!p) {
        p = (pend_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                sizeof *p);
        if (p) TlsSetValue(g_tls_pend, (LPVOID)p);   /* 分配失败下次重试 */
    }
    return p;
}

/* 诊断计数器（写入方独占，reader 只读；失败静默） */
static void diag_inc(DWORD off)
{
    if (g_meta) InterlockedIncrement((volatile LONG *)&g_meta[off / 4]);
}

static void diag_or(DWORD off, LONG bits)
{
    if (g_meta) InterlockedOr((volatile LONG *)&g_meta[off / 4], bits);
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
/* resolve_publish：pending 事件的身份解析 + DPS 语义过滤 + 发布          */
/*   v10.32 起**唯一调用点** = report_settle，调用时机在 ctor 返回之后， */
/*   此时 ctor 内部的两次 GetHandle 已把句柄缓存建好（见 pend_t 上方说明）。*/
/* ------------------------------------------------------------------ */

static void resolve_publish(pend_t *p, DWORD has_ty, DWORD ty, DWORD d_ov)
{
    DWORD atk_h = 0, vic_h = 0;
    DWORD at, vt, ai = 0, ag = 0, vg = 0;
    void *aobj = NULL, *vobj = NULL, *oobj = NULL;
    DWORD acard = 0, vcard = 0, ocard = 0;
    int   fb_a = 0, fb_v = 0;
    LONG  why = 0;

    if (!p->atk_obj || !p->vic_obj) {    /* ctor 自身早退条件：不该到这 */
        diag_or(META_DIAG_WHY, 2);
        goto drop;
    }

    vt = identify(p->vic_obj, &vic_h, &vobj, &vcard, &fb_v);
    at = identify(p->atk_obj, &atk_h, &aobj, &acard, &fb_a);
    if (fb_a || fb_v) diag_inc(META_DIAG_FB);

    /* 判定分布直方图（诊断「误过滤」的核心证据） */
    if (g_meta) {
        g_meta[(META_DIAG_HISTA + (at & 7) * 4) / 4]++;
        g_meta[(META_DIAG_HISTV + (vt & 7) * 4) / 4]++;
        g_meta[META_DIAG_LASTA / 4] = at;
        g_meta[META_DIAG_LASTV / 4] = vt;
    }

    /* 受击者必须为敌方（vt == 1），其余一律丢弃 */
    if (vt != 1) { why |= 4; goto drop; }

    /* 攻击链终点必须为玩家侧（at/ot ∈ {3,4,5,6}） */
    if (at == 2) {
        /* Missile 归因：owner 句柄 = [Missile+0x48]（ctor sub_442C40 实锤）。
         * 该句柄在导弹创建时就已存在，与惰性缓存无关。 */
        DWORD ow_h = 0, ot;
        if (!aobj || !safe_read32((const BYTE *)aobj + 0x48, &ow_h) || !ow_h) {
            why |= 16; goto drop;
        }
        ot = resolve_cached(ow_h, &oobj, &ocard);
        if (ot < 3 || ot > 6) { why |= 32; goto drop; }
        ag = ow_h >> 16;                 /* owner 的真 gen */
        ai = ocard;
    } else if (at >= 3 && at <= 6) {
        ag = inst_id(atk_h, p->atk_obj); /* 句柄可用则真 gen，否则指针低位 */
        ai = acard;
    } else {
        why |= 8; goto drop;             /* 敌方 / 未知 / 解析失败 */
    }

    if (g_meta) g_meta[META_DIAG_LASTW / 4] = 0;   /* 清掉上次丢弃原因 */

    /* 受击方标识：与 ag 同构（句柄 gen，缺失时退化为指针低位）。
     * 受击者经 vt==1 过滤后必为 Enemy，所以 vg 恒有值。 */
    vg = inst_id(vic_h, p->vic_obj);

    /* 受击方种类键 vi（v10.22 定稿）：模式槽索引 = (pval − 0x200000) >> 4。
     * pval = *( *(vobj+4) + 5Ch )，落 .text 0x201250–0x2129E0 模式处理代码区、
     * 16 字节对齐，右移 4 即槽号（与实机点阵逐一对照验证无误）。
     * 例：0x212990 → 4761。越界/不可读时置 0（前端单列一桶）。 */
    {
        DWORD param = 0, pval = 0, vi = 0;
        if (vobj && safe_read32((const BYTE *)vobj + 4, &param) && param >= 0x10000) {
            safe_read32((const BYTE *)(UINT_PTR)param + 0x5C, &pval);
            if (pval >= 0x200000u && pval < 0x400000u)
                vi = (pval - 0x200000u) >> 4;
        }
        /* v10.31：d_ov = 属性表伤害总量（DCC328），非 0 优先于 ctor 侧读数 */
        publish_event(p->gf, d_ov ? d_ov : p->d, ai, ag, vg, vi, has_ty, ty);
    }
    return;

drop:
    if (why) diag_or(META_DIAG_WHY, why);
    if (g_meta) g_meta[META_DIAG_LASTW / 4] = (DWORD)why;
    diag_inc(META_DIAG_DROP);
}

/* ------------------------------------------------------------------ */
/* report_ctor：主 hook 入口只做「取值 + 暂存」，不做身份解析。          */
/*   atk/vic 为对象指针，dptr 为伤害值指针（入口终值）。                 */
/*   解析推迟到副 hook（ctor 之后）—— 见 pend_t 上方惰性句柄说明。       */
/* ------------------------------------------------------------------ */

static void report_ctor(DWORD atk_obj, DWORD vic_obj, const DWORD *dptr)
{
    DWORD dmg, gf;
    pend_t *p;

    if (!g_shm) return;                  /* SHM 创建失败 → 通道静默禁用    */
    diag_inc(META_DIAG_CTOR);            /* 诊断：主 hook 命中             */

    /* 游戏自身早退条件同步（arg_4/arg_8 任一为 0 → 原函数直接返回） */
    if (!atk_obj || !vic_obj) return;

    /* FR-1 过滤：伤害值==0 → 静默丢弃（d = *arg_C，入口即终值） */
    if (!safe_read32(dptr, &dmg) || dmg == 0) {
        diag_or(META_DIAG_WHY, 1);
        return;
    }

    /* 时间轴：GameFrame（暂停/倍速免疫） */
    gf = 0;
    safe_read32((const BYTE *)(UINT_PTR)g_base + RVA_GFRAME, &gf);
    if (g_meta) g_meta[META_DIAG_GF / 4] = gf;

    /* v10.32：主 hook **只登记、不发布**。发布权唯一属于结算 hook ——
     * 这样每条对外事件都必然来自同一次 CDamageProperty 读取，ty 与 d 同源。
     *   · 无槽位（结算 hook 未装 / TLS 分配失败）→ 本事件无处落地，丢弃；
     *   · 槽位被占（上一事件还没等到结算点）→ 旧事件丢弃，槽被新事件覆盖。
     *     丢弃是刻意的：宁可缺一条，也不产出与 ty 无关的半成品事件。 */
    p = g_hook_settle ? pend_get() : NULL;
    if (!p) {
        diag_inc(META_DIAG_NOSLOT);
        return;
    }
    /* 槽只有一个：新节点直接覆盖旧登记。旧登记若还没等到它的结算，就随覆盖
     * 自然消失 —— 不补发、不记账（v10.33 起连「被挤占」计数都去掉：那不是
     * 一类需要统计的事件，只是单槽的固有行为）。 */
    p->gf = gf; p->d = dmg;
    p->atk_obj = atk_obj; p->vic_obj = vic_obj;
    p->used = 1;
    diag_inc(META_DIAG_PEND);
}

/* ------------------------------------------------------------------ */
/* 主 hook 本体（v1.5 入口拦截）：参数在入口栈上全量可得，无需偷换返回  */
/* 地址 —— pushad 全寄存器保护 → 取栈上 arg_4/arg_8/arg_C 调 report    */
/* → popad → jmp trampoline。无 TLS 状态，天然重入安全（节点创建路径   */
/* 嵌套也不产生状态覆写问题）。                                        */
/* 入口栈布局：[esp]=ret / [esp+4]=arg_0（不消费）/ [esp+8]=arg_4 攻击 */
/* 者对象 / [esp+0C]=arg_8 受击者对象 / [esp+10]=arg_C 伤害值指针。    */
/* ------------------------------------------------------------------ */

__declspec(naked) static void hook_ctor(void)
{
    __asm {
        pushad
        mov     eax, [esp+40]           /* arg_4 攻击者对象（32B+8）    */
        mov     ecx, [esp+44]           /* arg_8 受击者对象             */
        mov     edx, [esp+48]           /* arg_C 伤害值指针             */
        push    edx
        push    ecx
        push    eax
        call    report_ctor
        add     esp, 12
        popad
        jmp     [g_tram]                /* 原函数 8 字节序言 + 回跳      */
    }
}

/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* 主 hook 创建（v10.30）：只 Create 不 Enable —— Create 仅建 trampoline
 * 并在 MinHook 内部记账（hook.c:579-655，不写目标内存），零足迹。
 * EXPECT_PROLOGUE 预校验保留：序言不符时显式拒建 + DbgView 报错。
 * 启用统一走 init_thread_proc 末尾的批量 Apply（见下）。              */
/* ------------------------------------------------------------------ */

static BOOL create_hook(void)
{
    BYTE *tgt = (BYTE *)(UINT_PTR)g_base + HOOK_RVA;

    if (memcmp(tgt, EXPECT_PROLOGUE, HOOK_PATCH_LEN) != 0) {
        /* 版本漂移保护：拒建 + DbgView 可见，游戏正常运行无感知。 */
        char msg[128];
        _snprintf(msg, sizeof msg - 1,
            "[dps] prologue mismatch @ RVA 0x%X (ctor hook), exe updated? "
            "hook skipped", HOOK_RVA);
        OutputDebugStringA(msg);
        return FALSE;
    }
    return MH_CreateHook(tgt, (void *)hook_ctor, &g_tram) == MH_OK;
}

/* ------------------------------------------------------------------ */
/* 副 hook：sub_5CAC50 入口。                                             */
/*   ecx   = 受击单位对象（this）→ 与 pending->vic_obj 做指针比较，唯一判据 */
/*   [esp+4] = CDamageHandle*    → 取 ty（sub_4F1E50）与 d（DCC328）      */
/*   指针相等才消费并发布；不等直接返回，pending 原样保留。              */
/*   与主 hook 同技法（入口拦截 + trampoline），无 TLS 偷换，重入安全。  */
/* ------------------------------------------------------------------ */

static BOOL g_logged_miss = FALSE;       /* 首次指针不符已留证            */
static BOOL g_logged_ok   = FALSE;       /* 首次配对成功已留证            */

static void report_settle(const void *handle, DWORD vic_obj)
{
    pend_t *p;
    DWORD ty = 0, d2 = 0, has_ty = 0;

    diag_inc(META_DIAG_TYHIT);           /* 诊断：副 hook 命中             */
    p = pend_get();
    if (!p || !p->used) {                /* 无前置创建：无可配对，跳过   */
        diag_inc(META_DIAG_NOPD);
        return;
    }

    /* ★ 唯一配对判据（v10.33）：受击单位对象指针相等。
     *   sub_5CAC50 的 ecx = 受击单位对象（sub_5CBBE0+0x4D5 里 ecx=ebx，
     *   [ebx+0Ch] 就是刚被扣减的 HP），与主 hook 的 arg_8 是同一实例。
     *   不等 → 这次结算不属于本次登记：直接返回，**不消费** pending，
     *   让它继续等属于自己的那次结算。不补发、不跨事件记账。 */
    if ((DWORD)(UINT_PTR)vic_obj != p->vic_obj) {
        diag_inc(META_DIAG_PMISS);
        if (!g_logged_miss) {            /* 首次不符 → DbgView 留证     */
            char msg[128];
            g_logged_miss = TRUE;
            _snprintf(msg, sizeof msg - 1,
                "[dps] pair miss (first): settle_this=0x%X pend_vic=0x%X",
                (unsigned)(UINT_PTR)vic_obj, (unsigned)p->vic_obj);
            OutputDebugStringA(msg);
        }
        return;
    }
    if (!g_logged_ok) {
        char msg[128];
        g_logged_ok = TRUE;
        _snprintf(msg, sizeof msg - 1,
            "[dps] pair ok (first): this=0x%X", (unsigned)(UINT_PTR)vic_obj);
        OutputDebugStringA(msg);
    }
    p->used = 0;                         /* 已确认同一次伤害 → 消费       */

    /* ① ty：唯一来源 = 游戏自身的 13 键重组器（纯读，无副作用）。
     * ⚠ v10.31 曾在此退化读 prop+0x1C —— 那是错的：sub_5CAC50 的 arg_0 是
     *   CDamageHandle（12 字节三元组：+0x0C 侧别标签 / +0x04 idA / +0x08 idB），
     *   不是 CDamageProperty；+0x1C 既越界也不含 ty。已删除，ty 读不到即省略。 */
    if (handle && g_fn_ty_reasm) {
        ty = g_fn_ty_reasm((void *)handle, NULL);
        has_ty = 1;
    }

    /* ② d：属性表里的伤害总量（DCC328，HP 结算实际扣血）；0 = 未设置 */
    if (handle && g_fn_get_prop)
        d2 = g_fn_get_prop((void *)handle, NULL,
                           (const void *)((const BYTE *)(UINT_PTR)g_base
                                          + RVA_KEY_D2));

    if (has_ty) diag_inc(META_DIAG_TYPAIR);
    resolve_publish(p, has_ty, ty, d2);  /* d2==0 → resolve 内退回 ctor 侧 d */
}

__declspec(naked) static void hook_settle(void)
{
    __asm {
        pushad
        mov     eax, [esp+36]           /* arg_0 = CDamageHandle*（32B+4）*/
        mov     edx, ecx                /* ecx = this = 受击单位对象     */
        push    edx                     /* 第 2 参：配对用的指针         */
        push    eax                     /* 第 1 参：取 ty/d 的 handle    */
        call    report_settle
        add     esp, 8
        popad
        jmp     [g_tram_t]              /* 原 5 字节序言 + 回跳          */
    }
}

/* 副 hook 创建（v10.30）：同主 hook，只 Create 不 Enable。失败 → 仅降级
 * ty（主链路照常，事件按缺省 ty 发布）——降级判定在批量启用处统一裁决。 */
static BOOL create_hook_settle(void)
{
    BYTE *tgt = (BYTE *)(UINT_PTR)g_base + HOOK_SETTLE_RVA;

    if (memcmp(tgt, EXPECT_PROLOGUE_SETTLE, HOOK_SETTLE_PATCH_LEN) != 0) {
        char msg[128];
        _snprintf(msg, sizeof msg - 1,
            "[dps] prologue mismatch @ RVA 0x%X (settle hook), exe updated? "
            "hook skipped, ty/d2 disabled", HOOK_SETTLE_RVA);
        OutputDebugStringA(msg);
        return FALSE;
    }
    return MH_CreateHook(tgt, (void *)hook_settle, &g_tram_t) == MH_OK;
}

/* ------------------------------------------------------------------ */
/* 批量启用（v10.30）：一次 MH_QueueEnableHook(MH_ALL_HOOKS) +
 * MH_ApplyQueued —— 仅一次 Freeze（挂起全部线程 + ProcessThreadIPs 修 EIP
 * + 写补丁 + 恢复），替代原先每钩一次 MH_EnableHook 的两次 Freeze。
 *   - 双钩均已 Create：同批翻转，无「主生效/副未装」中间窗口；
 *   - 仅单钩 Create 成功：ALL_HOOKS 只含它，等价旧单钩降级模式；
 *   - ApplyQueued 部分失败（循环内首个 EnableHookLL 失败即返回，先前钩子
 *     可能已生效）：QueueDisableHook(MH_ALL_HOOKS) + ApplyQueued 全量回滚，
 *     保守回到无钩态 —— EnableHookLL 的现实失败源仅 VirtualProtect。
 * 返回 TRUE = 队列应用成功（已 Create 的钩子全部启用）；
 * 启用与否的最终裁决（g_hooked / g_hook_settle）由调用方按 Create 结果合并。 */
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
    BOOL c_main, c_settle, applied;      /* v10.30 批量装钩三态 */

    if (GetEnvironmentVariableA("DPS_ON", tmp, sizeof tmp) &&
        lstrcmpA(tmp, "0") == 0)
        return 0;                        /* 显式禁用全部 hook 与 SHM 写入 */

    g_base = (DWORD)(UINT_PTR)GetModuleHandleA(NULL);

    /* VEH 探针护盾必须先于 hook 安装（探针 AV 永不进 SEH 链）。 */
    g_tls_probe = TlsAlloc();
    g_veh = AddVectoredExceptionHandler(1, probe_veh);

    shm_init();

    if (MH_Initialize() != MH_OK)
        goto diag;                       /* 引擎初始化失败：双 hook 均不装 */

    /* v10.30 批量装钩：先集中 Create（含序言校验，零补丁零生效），
     * 再单次 Queue+Apply 启用 —— 全线程 Freeze 仅一次（I-001 改进）。
     * 启用最终态 = Create 结果 ∧ Apply 结果：任一 Create 失败者不启用，
     * 全部失败/回滚则双钩均未生效（游戏无感知，仅 DbgView 可见）。 */
    c_main   = create_hook();
    c_settle = create_hook_settle();
    applied  = (c_main || c_settle) ? apply_queued_enable() : FALSE;
    g_hooked      = (BOOL)(c_main   && applied);
    g_hook_settle = (BOOL)(c_settle && applied);

    /* v10.31：属性读取原语按序言校验后绑定；不符 → 该项降级（ty 直读 /
     * d 用 ctor 侧值），绝不把漂移过的地址当函数调。 */
    {
        const BYTE *hp = (const BYTE *)(UINT_PTR)g_base + RVA_GET_PROP;
        const BYTE *tp = (const BYTE *)(UINT_PTR)g_base + RVA_TY_REASM;
        if (memcmp(hp, PROLOGUE_GET_PROP, sizeof PROLOGUE_GET_PROP) == 0)
            g_fn_get_prop = (fn_get_prop)hp;
        if (memcmp(tp, PROLOGUE_TY_REASM, sizeof PROLOGUE_TY_REASM) == 0)
            g_fn_ty_reasm = (fn_ty_reasm)tp;
    }

    /* 副 hook + pending 槽：失败仅降级 ty（ty 全局缺失 + 诊断计数）。 */
    g_tls_pend = TlsAlloc();

    /* 诊断：安装状态写入 SHM flags + DbgView 单行摘要（排查"无数据"用） */
    if (g_meta) {
        DWORD flags = 4u;               /* bit2 SHM 就绪                  */
        if (g_hooked) flags |= 1u;      /* bit0 主 hook                   */
        if (g_hook_settle) flags |= 2u;     /* bit1 settle hook（ty+d2）      */
        g_meta[META_DIAG_FLAGS / 4] = flags;
    }
    {
        char msg[192];
        _snprintf(msg, sizeof msg - 1,
            "[dps] init: rel=%s impl=v10.33 shm=%d main_hook=%d(RVA 0x%X) "
            "settle_hook=%d(RVA 0x%X) ty_src=%d d_src=%d base=0x%X",
            DPS_REL_VER, g_shm ? 1 : 0, g_hooked, HOOK_RVA,
            g_hook_settle, HOOK_SETTLE_RVA,
            g_fn_ty_reasm ? 1 : 0, g_fn_get_prop ? 1 : 0, (unsigned)g_base);
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
