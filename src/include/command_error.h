/**
 * 本文档可整合各系统定义的命令码和错误码，按照系统编号区分不同系统
*/

/* 证明服务框架系统（ASFS），系统编号：1004 */

/* 命令码 */
// SOC
#define            MOD_NODE_REGISTER                            10040001        // 向节点下发注册命令
// KMS

// AS


/* 错误码、返回码 */
// 通用
#define            RC_UNKNOWN_EXCEOTION                         9999            // 系统发生未知错误
#define            RC_SUCCESS                                   0               // 运行成功

// 参数类
#define            RC_BAD_PARAM_SOC_CURL                        0100            // 运行SOC的curl参数错误
#define            RC_BAD_PARAM_NODE_TYPE                       0110            // 节点类型不在解析范围内

// 注册功能
// 流程1：SOC下发命令，节点进行响应（生成注册request）
#define            RC_REGISTER_NODE_COLLECT_INFO_FAIL           1000            // 节点发起注册前处理发生错误
#define            RC_REGISTER_SOC_CONNECT_NODE_FAIL            1001            // 节点无响应（httpd没有开启）
#define            RC_REGISTER_TPM_INIT_FAIL                    1002            // 节点TPM连接失败
#define            RC_REGISTER_COLLECT_FAIL                     1003            // 节点收集信息失败
#define            RC_REGISTER_NODE_EXECUTE_FAIL                1004            // 节点curl执行失败
#define            RC_REGISTER_NODE_CONNECT_SOC_FAIL            1005            // 节点连接SOC失败
// SGX 注册过程错误
#define            RC_REGISTER_SGX_NODE_COLLECT_QUOTE_FAIL      1101            // ENCLAVE收集quote发生错误
#define            RC_REGISTER_SGX_NODE_COLLECT_COLLATERAL_FAIL 1102            // ENCLAVE收集collateral发生错误
#define            RC_REGISTER_SGX_COLLECT_FAIL                 1003            // SGX节点收集信息失败

// 流程2：SOC生成验证的request，并发送给KMS
#define            RC_REGISTER_SOC_DEAL_REGISTER_FAIL           2000            // SOC处理节点注册过程发生错误
#define            RC_REGISTER_SOC_CONNECT_MYSQL_FAIL           2001            // 连接MySQL失败
#define            RC_REGISTER_CHECK_REGISTER_FAIL              2002            // 查询节点是否注册发生错误
#define            RC_REGISTER_INSERT_NODE_INFO_FAIL            2003            // 新节点注册信息录入发生错误
#define            RC_REGISTER_READ_KMS_CFG_FAIL                2004            // 读取KMS信息文件失败
#define            RC_REGISTER_CONNECT_KMS_FAIL                 2005            // KMS无响应
#define            RC_REGISTER_PARSE_VERIFY_RES_FAIL            2006            // 解析验证结果发生错误
// 流程3：KMS验证Node EK证书并返回验证结果（包括验证成功时生成密钥和证书）
#define            RC_REGISTER_KMS_CERT_AND_KEY_FAIL            3000            // KMS验证EK证书以及生成密钥阶段发生错误
#define            RC_REGISTER_KMS_CONNECT_MYSQL_FAIL           3001            // KMS连接MySQL失败
#define            RC_REGISTER_KMS_QUERY_MYSQL_FAIL             3002            // KMS查询数据库失败
#define            RC_REGISTER_KMS_VERIFY_EK_SUCCESS            3003            // KMS验证EK通过
#define            RC_REGISTER_KMS_VERIFY_EK_FAIL               3004            // KMS验证EK失败
#define            RC_REGISTER_KMS_NOT_INITIALIZED              3005            // KMS未初始化，没有私钥
#define            RC_REGISTER_KMS_CREATE_CA_CSR_FAIL           3006            // KMS生成CA CSR失败
#define            RC_REGISTER_KMS_CREATE_CA_CERT_FAIL          3007            // KMS生成CA证书失败
#define            RC_REGISTER_KMS_SAVE_CA_CERT_FAIL            3007            // KMS保存CA证书失败
#define            RC_REGISTER_KMS_CREATE_AK_CERT_FAIL          3008            // KMS生成AK证书失败
#define            RC_REGISTER_KMS_SAVE_AK_CERT_FAIL            3009            // KMS保存AK证书失败
#define            RC_REGISTER_KMS_INSERT_AK_FAIL               3010            // KMS插入AK失败
#define            RC_REGISTER_KMS_INSERT_MS_FAIL               3011            // KMS插入mastersecret失败
#define            RC_REGISTER_KMS_CONVERT_AK_FAIL              3012            // KMS转换AK失败
// 流程4：SOC解析验证结果，修改Node注册状态，并返回注册结果给Node
#define            RC_REGISTER_NODE_REGISTER_SUCCEED            4000            // 新节点注册成功
#define            RC_REGISTER_VERIFY_CERT_FAIL                 4001            // 验证EK证书失败
#define            RC_REGISTER_NODE_REGISTER_MULTIPLE           4002            // 节点重复注册
#define            RC_REGISTER_UPDATE_NODE_INFO_FAIL            4003            // 更新节点注册状态发生错误

//证明功能
//流程1：SOC下发命令，节点进行响应（生成证明request）
#define            RC_ATTEST_NODE_FAIL                          1000            // 节点发起证明前处理发生错误
#define            RC_ATTEST_CONNECT_NODE_FAIL                  1001            // 节点无响应（httpd没有开启）
#define            RC_ATTEST_NODE_EXECUTE_FAIL                  1002            // 节点执行curl错误
//流程2：节点向AS发起挑战
#define            RC_ATTEST_AS_DEAL_CHALLENGE_FAIL             2000            // AS处理节点挑战过程发生错误
#define            RC_ATTEST_AS_CONNECT_MYSQL_FAIL              2001            // AS连接MySQL失败
#define            RC_ATTEST_AS_QUERY_MYSQL_FAIL                2002            // AS查询数据库失败
#define            RC_ATTEST_NODE_NOT_REGIST                    2003            // 节点未注册
#define            RC_ATTEST_NODE_NOT_QUERY_RESULT              2004            // AS未获得查询结果
#define            RC_ATTEST_AS_GENERATE_RANDOM_FAIL            2005            // AS生成随机数错误
#define            RC_ATTEST_AS_INSERT_MYSQL_FAIL               2006            // AS插入数据库失败

//流程3：节点生成证明证据
#define            RC_ATTEST_NODE_GENERATE_FAIL                 3000            // 节点生成证明证据失败
#define            RC_ATTEST_GET_QUOTE_FAIL                     3001            // 节点create quote失败
#define            RC_ATTEST_READ_AKCERT_FAIL                   3002            // 节点读取ak失败

//流程4：AS验证证明证据并生成token
#define             RC_ATTEST_AS_VERIFY_FAIL                    4000            // AS验证证明证据失败
#define             RC_ATTEST_VERIFY_AK_FAIL                    4001            // AK验证错误
#define             RC_ATTEST_AK_COVERT_FAIL                    4002            // AK转换失败
#define             RC_ATTEST_OPEN_FILE_FAIL                    4003            // 证明时打开文件失败
#define             RC_ATTEST_QUOTE_INVALID                     4004            // quote字符串无效
#define             RC_ATTEST_CHECK_QUOTE_FAIL                  4005            // CHECK QUOTE 失败
#define             RC_ATTEST_TOKEN_SAVE_FAIL                   4006            // TOKEN保存失败

//流程4：SOC向AS验证token的有效性
#define            RC_ATTEST_CHECKTOKEN_FAIL                   5000            // 验证token失败
#define            RC_ATTEST_CHECKTOKEN_UUID_FAIL              5001            // 验证token的uuid失败
#define            RC_ATTEST_CHECKTOKEN_EXPIRED                5002            // 验证token的有效期失效
#define            RC_ATTEST_CHECKTOKEN_SIGN_FAIL              5003            // 验证token的签名失效
#define            RC_ATTEST_CHECKTOKEN_FORMAT_FAIL            5004            // 获取token格式错误

//KMS管理功能
#define            RC_KMS_CONNECT_MYSQL_FAIL                   1000            // KMS连接数据库失败
#define            RC_KMS_QUERT_MYSQL_FAIL                     1001            // KMS查询数据库失败
#define            RC_KMS_UUIS_INVALID                         1002            // uuid无效
#define            RC_KMS_NOT_QUERY_RESULT                     1003            // KMS未获得查询结果
#define            RC_KMS_UPDATE_MYSQL_RESULT                  1004            // KMS更新数据库失败
#define            RC_KMS_CERT_REVOKED                         1005            // 证书已被撤销
#define            RC_KMS_OPERATE_FAIL                         1000

/* 软硬件协同防护系统（HSCPS），系统编号：1005 */

// 命令码


// 错误码、返回码

// SGX硬件错误
#define            RC_SGX_INITIALIZE_FAIL                      9100             // SGX enclave 启动失败