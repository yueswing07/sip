/*
 ===============================================================
 GBT28181 基于eXosip2,osip库实现注册UAC功能
 作者：程序人生
 博客地址：http://blog.csdn.net/hiwubihe
 QQ：1269122125
 注：请尊重原作者劳动成果，仅供学习使用，请勿盗用，违者必究！
 ================================================================
 */

#include <iostream>
#include <string>
#include <sstream>
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_port.h>

#include <eXosip2/eXosip.h>
#include <eXosip2/eX_setup.h>
#include <eXosip2/eX_register.h>
#include <eXosip2/eX_options.h>
#include <eXosip2/eX_message.h>
//#include <arpa/inet.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <unistd.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace std;

//本地监听IP
#define LISTEN_ADDR ("61.149.194.174")
//本地监听端口
#define UACPORT ("5061")
#define UACPORTINT (5061)
//本UAC地址编码
#define UACCODE ("30000025")
//本地UAC密码
#define UACPWD ("123456")
//远程UAS IP
#define UAS_ADDR ("47.112.105.194") // 47.112.105.194 192.168.2.251
//远程UAS 端口
#define UAS_PORT ("5060")
//超时
#define EXPIS 3600

//当前服务状态 1 已经注册 0 未注册
static int iCurrentStatus;
//注册成功HANDLE
static int iHandle = -1;

char *pSDP = "v=0\r\n"
                      "o=anonymous 0 0 IN IP4 0.0.0.0\r\n"
                      "t=1 10\r\n"
                      "a=username:rainfish\r\n"
                      "a=password:123\r\n";

enum REGISTER_TYPE{REGISTER,UNREGISTER,REFRESHED};
static REGISTER_TYPE registerType=REGISTER;
/* 该方法一般取出的ip为 127.0.0.1 ,windows也可以使用此类方法,但是需要略为改动*/
int get_local_ip_using_hostname(char *str_ip) 
{
    int status = -1;
    int i = 0;
    char buf[128] = {0};
    char *local_ip = NULL;
#ifdef WIN32
    WSADATA wsadata;
    if(0 != WSAStartup(MAKEWORD(2, 2), &wsadata))   //初始化
    {
        printf("初始化网络环境失败!");
        return -1;
    }
#endif
    if (gethostname(buf, sizeof(buf)) == 0)
    {
        struct hostent *temp_he;
        temp_he = gethostbyname(buf);
        if (temp_he) 
        {
            char **pptr = temp_he->h_addr_list;
            for(; *pptr != NULL; pptr++)
            {
                local_ip = NULL;
                local_ip = inet_ntoa(*(struct in_addr *)(*pptr));
                if(local_ip)
                {
                    strcpy(str_ip, local_ip);
                    status = 0;
                    printf("ip:%s",local_ip);
                    if(strcmp("127.0.0.1", str_ip))
                    {
                        //break;
                    }
                }
            }
        }
    }
#ifdef WIN32
    WSACleanup();
#endif
    return status;
}

//SIP From/To 头部
class CSipFromToHeader
{
public:
    CSipFromToHeader()
    {
    }
    ~CSipFromToHeader()
    {
    }
    void SetHeader(string addrCod, string addrI, string addrPor)
    {
        addrCode = addrCod;
        addrIp = addrI;
        addrPort = addrPor;
    }
    string GetFormatHeader()
    {
        std::stringstream stream;
        stream << "sip:" << addrCode << "@" << addrIp << ":" << addrPort;
        return stream.str();
    }
    //主机名称
    string GetCode()
    {
        std::stringstream stream;
        stream << addrCode;
        return stream.str();
    }
    //主机地址
    string GetAddr()
    {
        std::stringstream stream;
        stream << addrIp;
        return stream.str();
    }
    //端口
    string GetPort()
    {
        std::stringstream stream;
        stream << addrPort;
        return stream.str();
    }

private:
    string addrCode;
    string addrIp;
    string addrPort;
};

//SIP Contract头部
class CContractHeader: public CSipFromToHeader
{
public:
    CContractHeader()
    {
    }
    ~CContractHeader()
    {
    }
    void SetContractHeader(string addrCod, string addrI, string addrPor)
    {
        SetHeader(addrCod, addrI, addrPor);
    }
    string GetContractFormatHeader()
    {

        std::stringstream stream;
        stream << "<sip:" << GetCode() << "@" << GetAddr() << ":" << GetPort()
                << ">";
        return stream.str();
    }
};

//发送注册信息
int SendRegister(int& registerId, CSipFromToHeader &from, CSipFromToHeader &to,
        CContractHeader &contact, const string& userName, const string& pwd,
        const int expires, int iType)
{
    cout << "=============================================" << endl;
    if (iType == 0)
    {
        cout << "注册请求信息：" << endl;
    }
    else if (iType == 1)
    {
        cout << "刷新注册信息：" << endl;
    }
    else
    {
        cout << "注销信息:" << endl;
    }
    cout << "registerId " << registerId << endl;
    cout << "from " << from.GetFormatHeader() << endl;
    cout << "to " << to.GetFormatHeader() << endl;
    cout << "contact" << contact.GetContractFormatHeader() << endl;
    cout << "userName" << userName << endl;
    cout << "pwd" << pwd << endl;
    cout << "expires" << expires << endl;
    cout << "=============================================" << endl;
    //服务器注册
    static osip_message_t *regMsg = 0;
    int ret;

    ::eXosip_add_authentication_info(userName.c_str(), userName.c_str(),
            pwd.c_str(), "MD5", NULL);
    eXosip_lock();
    //发送注册信息 401响应由eXosip2库自动发送
    if (0 == registerId)
    {
        // 注册消息的初始化
        registerId = ::eXosip_register_build_initial_register(
                from.GetFormatHeader().c_str(), to.GetFormatHeader().c_str(),
                contact.GetContractFormatHeader().c_str(), expires, &regMsg);
        if (registerId <= 0)
        {
            return -1;
        }
    }
    else
    {
        // 构建注册消息
        ret = ::eXosip_register_build_register(registerId, expires, &regMsg);
        if (ret != OSIP_SUCCESS)
        {
            return ret;
        }
        //添加注销原因
        if (expires == 0)
        {
            osip_contact_t *contact = NULL;
            char tmp[128];

            osip_message_get_contact(regMsg, 0, &contact);
            {
                sprintf(tmp, "<sip:%s@%s:%s>;expires=0",
                        contact->url->username, contact->url->host,
                        contact->url->port);
            }
            //osip_contact_free(contact);
            //reset contact header
            osip_list_remove(&regMsg->contacts, 0);
            osip_message_set_contact(regMsg, tmp);
            osip_message_set_header(regMsg, "Logout-Reason", "logout");
        }
    }
    // 发送注册消息
    ret = ::eXosip_register_send_register(registerId, regMsg);
    if (ret != OSIP_SUCCESS)
    {
        registerId = 0;
    }eXosip_unlock();

    return ret;
}

//注册
void Register()
{
    if (iCurrentStatus == 1)
    {
        cout << "当前已经注册" << endl;
        return;
    }
	registerType=REFRESHED;
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //发送注册信息
    int registerId = 0;
    if (0 > SendRegister(registerId, stFrom, stTo, stContract, UACCODE, UACPWD,
            3000, 0))
    {
        cout << "发送注册失败" << endl;
        return;
    }
    // iCurrentStatus = 1;
    iHandle = registerId;
}
//刷新注册
void RefreshRegister()
{
    if (iCurrentStatus == 0)
    {
        cout << "当前未注册，不允许刷新" << endl;
        return;
    }
	registerType=REFRESHED;
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //发送注册信息
    if (0 > SendRegister(iHandle, stFrom, stTo, stContract, UACCODE, UACPWD,
            3000, 1))
    {
        cout << "发送刷新注册失败" << endl;
        return;
    }
}
//注销
void UnRegister()
{
    if (iCurrentStatus == 0)
    {
        cout << "当前未注册，不允许注销" << endl;
        return;
    }
	registerType=UNREGISTER;
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //发送注册信息
    if (0 > SendRegister( iHandle, stFrom, stTo, stContract, UACCODE, UACPWD,
            0, 2))
    {
        cout << "发送注销失败" << endl;
        return;
    }
    iCurrentStatus = 0;
    iHandle = -1;
}
// 加入课堂
void enterClass(){

}
// 退出课堂
void leaveClass()
{
}
// 指定互动
void assignInteraction()
{
}
// 取消互动
void cancelInteraction()
{
}
// 共享课件
void shareCourseware()
{
}
// 取消共享课件
void cancelCourseware()
{
}
// 切换镜头
void switchCamera()
{
}
static void help()
{
    const char
            *b =
    "-------------------------------------------------------------------------------\n"
    "SIP Library test process - uac v 1.0 (June 13, 2014)\n\n"
    "SIP UAC端 注册,刷新注册,注销实现\n\n"
    "Author: 程序人生\n\n"
    "博客地址:http://blog.csdn.net/hiwubihe QQ:1269122125\n\n"
    "-------------------------------------------------------------------------------\n"
    "\n"
    "              0:Register\n"
    "              1:RefreshRegister\n"
    "              2:UnRegister\n"
    "              3:clear scream\n"
    "              4:exit\n"
    "              5:enterClass\n"
    "              6:leaveClass\n"
    "              7:assignInteraction\n"
    "              8:cancelInteraction\n"
    "              9:shareCourseware\n"
    "              10:cancelCourseware\n"
    "-------------------------------------------------------------------------------\n"
    "\n";
    fprintf(stderr, b, strlen(b));
    cout << "please select method :";
}
//服务处理线程
void *serverHandle(void *pUser)
{
//    sleep(3);
    help();
    char ch = getchar();
    getchar();
    while (1)
    {
        switch (ch)
        {
        case '0':
            //注册
            Register();
            break;
        case '1':
            //刷新注册
            RefreshRegister();
            break;
        case '2':
            //注销
            UnRegister();
            break;
        case '3':
            if (system("clear") < 0)
            {
                cout << "clear scream error" << endl;
                exit(1);
            }
            break;
        case '4':
            cout << "exit sipserver......" << endl;
            getchar();
            exit(0);
        case '5':
            enterClass();
            break;
        case '6':
            leaveClass();
            break;
        case '7':
            assignInteraction();
            break;
        case '8':
            cancelInteraction();
            break;
        case '9':
            shareCourseware();
            break;
        case '10':
            cancelCourseware();
            break;
        default:
            cout << "select error" << endl;
            break;
        }
        cout << "press any key to continue......" << endl;
        getchar();
        help();
        ch = getchar();
        getchar();
    }
    return NULL;
}

//事件处理线程
//DWORD WINAPI eventHandle(LPVOID lpParameter)
void *eventHandle(void *pUser)
{
    eXosip_event_t* osipEventPtr = (eXosip_event_t*) pUser;
    switch (osipEventPtr->type)
    {
        //需要继续验证REGISTER是什么类型
        case EXOSIP_REGISTRATION_SUCCESS:
            cout<<"REGISTRATION_SUCCESS 收到状态码:"<<osipEventPtr->response->status_code<<"报文"<<endl;
            if(registerType==REFRESHED) 
			iCurrentStatus = 1;
			if(registerType==UNREGISTER) 
			iCurrentStatus = -1;
            break;
        case EXOSIP_REGISTRATION_FAILURE:
            cout<<"REGISTRATION_SUCCESS 收到状态码:"<<osipEventPtr->response->status_code<<"报文"<<endl;
            cout<<"发送鉴权报文"<<endl;
            Register();
            break;
		case EXOSIP_REGISTRATION_REFRESHED:
			cout<<"收到状态码:"<<osipEventPtr->response->status_code<<"报文"<<endl;
            cout<<"REFRESHED 成功"<<endl;
            break;
		case EXOSIP_REGISTRATION_TERMINATED:
			cout<<"收到状态码:"<<osipEventPtr->response->status_code<<"报文"<<endl;
            if(osipEventPtr->response->status_code == 200)
            {
                cout<<"TERMINATED 成功"<<endl;
            }
            else
            {
                cout<<"注册失败"<<endl;
            }
            break;
        default:
            cout << "The sip event type that not be precessed.the event "
                "type is : " << osipEventPtr->type << endl;
            break;
    }
    eXosip_event_free(osipEventPtr);
    return NULL;
}

struct Config
{
    int uacPortInt;
    char listenAddr[128];
    char uacPort[16];
    char uacCode[64];
	char uacPwd[64];
	char uasAddr[64];
	char uasPort[16];
	int expis;
} sConfig;
void readCfg(char *filename, struct Config* sConfig);
/**
 * read config from httpd.conf 
 * parameters : file name 
 * return 
 */
void readCfg(char *filename, struct Config* sConfig)
{
    FILE *pf = NULL;
    char buf[2048];
    int i = 0,j = 0;
    char key[128];
    char val[128];

    pf = fopen(filename, "r+");
    if (NULL==pf){
        perror("open config file error. use default config.");
        return;
    }
    while(!feof(pf)) {
        fgets(buf,2048,pf);
        i = 0; j = 0;
        printf("%s\n", buf);
        // get key 
        while (!ISspace(buf[i]) && (i < strlen(buf) - 1))
        {
            key[j] = buf[i];
            i++;
            j++;
        }
        key[j] = 0;
        printf("%s\n", key);

        if ('#'==key[0]) continue;
        // get val
        i++; j=0;
        while (!ISspace(buf[i]) && (i < strlen(buf) - 1))
        {
            val[j] = buf[i];
            i++;
            j++;
        }
        val[j] = 0;
        printf("%s\n", val);

        if( strcasecmp(key,"port")==0 ) {
            sConfig->port = atoi(val);
        }

        if( strcasecmp(key,"rootDir")==0 ) {
            strncpy(sConfig->rootDir,val,128);
        }
    }
    fclose(pf);
}

int main()
{

    char* configFilename = "sip.conf";
	sConfig config;
	readCfg(configFilename,config);
	iCurrentStatus = 0;
    //库处理结果
    int result = OSIP_SUCCESS;
    //初始化库
    if (OSIP_SUCCESS != (result = eXosip_init()))
    {
        printf("eXosip_init failure.\n");
        return 1;
    }
    cout << "eXosip_init success." << endl;
    eXosip_set_user_agent(NULL);
    //监听
    if (OSIP_SUCCESS != eXosip_listen_addr(IPPROTO_UDP, NULL, UACPORTINT,
            AF_INET, 0))
    {
        printf("eXosip_listen_addr failure.\n");
        return 1;
    }
    //设置监听网卡
    if (OSIP_SUCCESS != eXosip_set_option(
    EXOSIP_OPT_SET_IPV4_FOR_GATEWAY,
            LISTEN_ADDR))
    {
        return -1;
    }
#ifdef _WIN32
    HANDLE handle = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)serverHandle,NULL,0,NULL);
    //serverHandle(NULL);
#else
    //开启服务线程
    pthread_t pthser;
    if (0 != pthread_create(&pthser, NULL, serverHandle, NULL))
    {
        printf("创建主服务失败\n");
        return -1;
    }
#endif
    //事件用于等待
    eXosip_event_t* osipEventPtr = NULL;
    //开启事件循环
    while (true)
    {
        //等待事件 0的单位是秒，500是毫秒
        osipEventPtr = ::eXosip_event_wait(0, 200);
        //处理eXosip库默认处理
        {
            //usleep(500 * 1000);
            eXosip_lock();
            //一般处理401/407采用库默认处理
            eXosip_default_action(osipEventPtr);
            eXosip_unlock();
        }
        //事件空继续等待
        if (NULL == osipEventPtr)
        {
            continue;
        }
#ifdef _WIN32
        eventHandle(osipEventPtr);
#else
        ////开启线程处理事件并在事件处理完毕将事件指针释放
        pthread_t pth;
        if (0 != pthread_create(&pth, NULL, eventHandle, (void*) osipEventPtr))
        {
            printf("创建线程处理事件失败\n");
            continue;
        }
#endif
        osipEventPtr = NULL;
    }
}