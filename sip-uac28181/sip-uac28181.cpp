/*
 ===============================================================
 GBT28181 基于eXosip2,osip库实现注册UAC功能
 作者：程序人生
 博客地址：http://blog.csdn.net/hiwubihe
 QQ：1269122125
 注：请尊重原作者劳动成果，仅供学习使用，请勿盗用，违者必究！
 ================================================================
 */
#include <stdio.h>
#include <string.h>
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
#define strcasecmp _stricmp
#else
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace std;

//当前服务状态 1 已经注册 0 未注册
static int iCurrentStatus;
//注册成功HANDLE
static int iHandle = -1;
int callId = -1;
int dialogId = -1;

char *pEnterClass = "v=0\r\n"
"o=- 3761910912 3761910915 IN IP4 47.112.105.194\r\n"
"s=butelmedia\r\n"
"t=0 0\r\n"
"m=audio 5061 RTP/AVP 98 97 99 0 8\r\n"
"c=IN IP4 61.149.194.174\r\n"
"a=sendrecv\r\n"
"a=rtpmap:98 speex/16000\r\n"
"a=rtpmap:97 speex/8000\r\n"
"a=rtpmap:99 speex/32000\r\n"
"a=rtpmap:0 PCMU/8000\r\n"
"a=rtpmap:8 PCMA/8000\r\n"
"a=ssrc:2066561799 cname:30000025\r\n"
"a=mid:audio-1\r\n"
"a=rtcp-mux\r\n"
"a=audiodesc:mic-audio\r\n"
//"m=video 5061 RTP/AVP 97\r\n"
//"c=IN IP4 61.149.194.174\r\n"
//"a=sendrecv\r\n"
//"a=rtpmap:97 H264/90000\r\n"
//"a=fmtp:97 profile-level-id=42e01e; packetization-mode=1\r\n"
//"a=ssrc:931412768 cname:30000025\r\n"
//"a=mid:video-1\r\n"
//"a=rtcp-mux\r\n"
//"a=videodesc:camera\r\n"
;
char *pShareCourseware = "v=0\r\n"
"o=- 3761910912 3761910915 IN IP4 47.112.105.194\r\n"
"s=butelmedia\r\n"
"t=0 0\r\n"
"m=audio 5061 RTP/AVP 98 97 99 0 8\r\n"
"c=IN IP4 61.149.194.174\r\n"
"a=sendrecv\r\n"
"a=rtpmap:98 speex/16000\r\n"
"a=rtpmap:97 speex/8000\r\n"
"a=rtpmap:99 speex/32000\r\n"
"a=rtpmap:0 PCMU/8000\r\n"
"a=rtpmap:8 PCMA/8000\r\n"
"a=ssrc:2066561799 cname:30000025\r\n"
"a=mid:audio-1\r\n"
"a=rtcp-mux\r\n"
"a=audiodesc:mic-audio\r\n"
;
char *pCancelCourseware = "v=0\r\n"
"o=- 3761910912 3761910915 IN IP4 47.112.105.194\r\n"
"s=butelmedia\r\n"
"t=0 0\r\n"
"m=audio 5061 RTP/AVP 98 97 99 0 8\r\n"
"c=IN IP4 61.149.194.174\r\n"
"a=sendrecv\r\n"
"a=rtpmap:98 speex/16000\r\n"
"a=rtpmap:97 speex/8000\r\n"
"a=rtpmap:99 speex/32000\r\n"
"a=rtpmap:0 PCMU/8000\r\n"
"a=rtpmap:8 PCMA/8000\r\n"
"a=ssrc:2066561799 cname:30000025\r\n"
"a=mid:audio-1\r\n"
"a=rtcp-mux\r\n"
"a=audiodesc:mic-audio\r\n"
;

char *pAssignInteraction = "<?xml version=\"1.0\"encoding=\"UTF-8\"?>"
"<Notify>"
"<SN>11</SN>"
"<CmdType>Interact</CmdType>"
"< UserIDList>"
"<UserID>30000026</UserID>"
"</UserIDList>"
"</Notify>";
char *pCancelInteraction = "<?xml version=\"1.0\"encoding=\"UTF-8\"?>"
"<Notify>"
"<SN>11</SN>"
"<CmdType>Interact</CmdType>"
"</Notify>";
char *pSwitchCamera = "<?xml version=\"1.0\"encoding=\"UTF-8\"?>"
"<Control>"
"<SN>11</SN>"
"<CmdType>CameraChange</CmdType>"
"<UserID>30000026</UserID>"
"</Control>";

enum REGISTER_TYPE{REGISTER,UNREGISTER,REFRESHED};
static REGISTER_TYPE registerType=REGISTER;
struct sConfig
{
    int uacPortInt;
    char listenAddr[128];
    char uacPort[16];
    char uacCode[64];
    char uacPwd[64];
    char uasAddr[64];
    char uasPort[16];
    char classId[64];
    int expis;
} ;
static struct sConfig sConfig;

/**
 * read sConfig from httpd.conf 
 * parameters : file name 
 * return 
 */
void readCfg(char *filename, struct sConfig* sConfig)
{
    FILE *pf = NULL;
    char buf[2048];
    int i = 0,j = 0;
    char key[128];
    char val[128];

    pf = fopen(filename, "r+");
    if (NULL==pf){
        perror("open sConfig file error. use default sConfig.");
        return;
    }
    while(!feof(pf)) {
        fgets(buf,2048,pf);
        i = 0; j = 0;
        printf("%s\n", buf);
        if ('#'==buf[0]) continue;
        // get key 
        while (!isspace(buf[i]) && (i < strlen(buf) - 1))
        {
            key[j] = buf[i];
            i++;
            j++;
        }
        key[j] = 0;
        printf("%s\n", key);

        //if ('#'==key[0]) continue;
        // get val
        i++; j=0;
        while (!isspace(buf[i]) && (i < strlen(buf) - 1))
        {
            val[j] = buf[i];
            i++;
            j++;
        }
        val[j] = 0;

        if( strcasecmp(key,"listenAddr")==0 ) {
            strncpy(sConfig->listenAddr,val,128);
        }
        if( strcasecmp(key,"uacPort")==0 ) {
            strncpy(sConfig->uacPort,val,128);
            sConfig->uacPortInt = atoi(val);
        }
        if( strcasecmp(key,"uacCode")==0 ) {
            strncpy(sConfig->uacCode,val,128);
        }
        if( strcasecmp(key,"uacPwd")==0 ) {
            strncpy(sConfig->uacPwd,val,128);
        }
        if( strcasecmp(key,"uasAddr")==0 ) {
            strncpy(sConfig->uasAddr,val,128);
        }
        if( strcasecmp(key,"uasPort")==0 ) {
            strncpy(sConfig->uasPort,val,128);
        }
        if( strcasecmp(key,"classId")==0 ) {
            strncpy(sConfig->classId,val,128);
        }
        if( strcasecmp(key,"expis")==0 ) {
            sConfig->expis = atoi(val);
        }
    }
    fclose(pf);
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
    stFrom.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    CSipFromToHeader stTo;
    stTo.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    CContractHeader stContract;
    stContract.SetContractHeader(sConfig.uacCode, sConfig.listenAddr, sConfig.uacPort);
    //发送注册信息
    int registerId = 0;
    if (0 > SendRegister(registerId, stFrom, stTo, stContract, sConfig.uacCode, sConfig.uacPwd,
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
    stFrom.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    CSipFromToHeader stTo;
    stTo.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    CContractHeader stContract;
    stContract.SetContractHeader(sConfig.uacCode, sConfig.listenAddr, sConfig.uacPort);
    //发送注册信息
    if (0 > SendRegister(iHandle, stFrom, stTo, stContract, sConfig.uacCode, sConfig.uacPwd,
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
    stFrom.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    // stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    // stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(sConfig.uacCode, sConfig.listenAddr, sConfig.uacPort);
    //发送注册信息
    if (0 > SendRegister( iHandle, stFrom, stTo, stContract, sConfig.uacCode, sConfig.uacPwd,
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
    osip_message_t *invite=NULL;
    int ret;
    char tmp[4096];

    CSipFromToHeader stFrom;
    stFrom.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    CSipFromToHeader stTo;
    stTo.SetHeader(sConfig.classId, sConfig.uasAddr, sConfig.uasPort);
    CContractHeader stContract;
    stContract.SetContractHeader(sConfig.uacCode, sConfig.listenAddr, sConfig.uacPort);
    ret = eXosip_call_build_initial_invite(&invite,stTo.GetFormatHeader().c_str(),stFrom.GetFormatHeader().c_str(),NULL,NULL); // "This is a call for conversation"
    if(ret!=0)
    {
        printf("Initial INVITE failed!\n");
    }
    //符合SDP格式，其中属性a是自定义格式，也就是说可以存放自己的信息，
    //但是只能有两列，比如帐户信息
    //但是经过测试，格式vot必不可少，原因未知，估计是协议栈在传输时需要检查的
    snprintf(tmp,4096,pEnterClass);

    osip_message_set_body(invite,tmp,strlen(tmp));
    osip_message_set_content_type(invite,"application/sdp");

    eXosip_lock();
    callId = eXosip_call_send_initial_invite(invite); //invite SIP INVITE message to send
    if (callId < 0)
    {
        printf("send INVITE failed!\n");
    }
    eXosip_unlock();
}
// 退出课堂
void leaveClass()
{
    int ret;

    eXosip_lock();
    ret = eXosip_call_terminate(callId,dialogId); //invite SIP INVITE message to send
    eXosip_unlock();
}
// 指定互动
void assignInteraction()
{
    osip_message_t *message=NULL;
    int ret;
    char tmp[4096];

    CSipFromToHeader stFrom;
    stFrom.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    CSipFromToHeader stTo;
    stTo.SetHeader(sConfig.classId, sConfig.uasAddr, sConfig.uasPort);
    CContractHeader stContract;
    stContract.SetContractHeader(sConfig.uacCode, sConfig.listenAddr, sConfig.uacPort);
    eXosip_message_build_request(&message,"MESSAGE",stTo.GetFormatHeader().c_str(),stFrom.GetFormatHeader().c_str(),NULL);
    //内容，方法 to from route 
    snprintf(tmp,4096,pAssignInteraction);
    osip_message_set_body(message,tmp,strlen(tmp));
    osip_message_set_content_type(message,"Application/MANSCDP+xml");
    eXosip_lock();
    ret = eXosip_message_send_request(message);
    if (ret < 0)
    {
        printf("send message failed!\n");
    }
    eXosip_unlock();
}
// 取消互动
void cancelInteraction()
{
    osip_message_t *message=NULL;
    int ret;
    char tmp[4096];

    CSipFromToHeader stFrom;
    stFrom.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    CSipFromToHeader stTo;
    stTo.SetHeader(sConfig.classId, sConfig.uasAddr, sConfig.uasPort);
    CContractHeader stContract;
    stContract.SetContractHeader(sConfig.uacCode, sConfig.listenAddr, sConfig.uacPort);
    eXosip_message_build_request(&message,"MESSAGE",stTo.GetFormatHeader().c_str(),stFrom.GetFormatHeader().c_str(),NULL);
    //内容，方法 to from route
    snprintf(tmp,4096,pCancelInteraction);
    osip_message_set_body(message,tmp,strlen(tmp));
    osip_message_set_content_type(message,"Application/MANSCDP+xml");
    eXosip_lock();
    ret = eXosip_message_send_request(message);
    if (ret < 0)
    {
        printf("send message failed!\n");
    }
    eXosip_unlock();
}
// 共享课件
void shareCourseware()
{
    osip_message_t *invite=NULL;
    int ret;
    char tmp[4096];

    CSipFromToHeader stFrom;
    stFrom.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    CSipFromToHeader stTo;
    stTo.SetHeader(sConfig.classId, sConfig.uasAddr, sConfig.uasPort);
    CContractHeader stContract;
    stContract.SetContractHeader(sConfig.uacCode, sConfig.listenAddr, sConfig.uacPort);
    ret = eXosip_call_build_initial_invite(&invite,stTo.GetFormatHeader().c_str(),stFrom.GetFormatHeader().c_str(),NULL,NULL); // "This is a call for conversation"
    if(ret!=0)
    {
        printf("Initial INVITE failed!\n");
    }
    snprintf(tmp,4096,pShareCourseware);

    osip_message_set_body(invite,tmp,strlen(tmp));
    osip_message_set_content_type(invite,"application/sdp");

    eXosip_lock();
    callId = eXosip_call_send_initial_invite(invite); //invite SIP INVITE message to send
    if (callId < 0)
    {
        printf("send INVITE failed!\n");
    }
    eXosip_unlock();
}
// 取消共享课件
void cancelCourseware()
{
}
// 切换镜头
void switchCamera()
{
    osip_message_t *message=NULL;
    int ret;
    char tmp[4096];

    CSipFromToHeader stFrom;
    stFrom.SetHeader(sConfig.uacCode, sConfig.uasAddr, sConfig.uasPort);
    CSipFromToHeader stTo;
    stTo.SetHeader(sConfig.classId, sConfig.uasAddr, sConfig.uasPort);
    CContractHeader stContract;
    stContract.SetContractHeader(sConfig.uacCode, sConfig.listenAddr, sConfig.uacPort);
    eXosip_message_build_request(&message,"MESSAGE",stTo.GetFormatHeader().c_str(),stFrom.GetFormatHeader().c_str(),NULL);
    //内容，方法 to from route
    snprintf(tmp,4096,pSwitchCamera);
    osip_message_set_body(message,tmp,strlen(tmp));
    osip_message_set_content_type(message,"Application/MANSCDP+xml");
    eXosip_lock();
    ret = eXosip_message_send_request(message);
    if (ret < 0)
    {
        printf("send message failed!\n");
    }
    eXosip_unlock();
}
static void help()
{
    const char
            *b =
    "-------------------------------------------------------------------------------\n"
    "              0:Register\n"
    "              1:RefreshRegister\n"
    "              2:UnRegister\n"
    "              3:clear scream\n"
    "              q:exit\n"
    "              5:enterClass\n"
    "              6:leaveClass\n"
    "              7:assignInteraction\n"
    "              8:cancelInteraction\n"
    "              9:shareCourseware\n"
    "              a:cancelCourseware\n"
    "              b:switchCamera\n"
    "-------------------------------------------------------------------------------\n"
    ;
    fprintf(stderr, b, strlen(b));
    cout << "please select method :";
}
//服务处理线程
void *serverHandle(void *pUser)
{
    // sleep(3);
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
        case 'q':
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
        case 'a':
            cancelCourseware();
            break;
        case 'b':
            switchCamera();
            break;
        default:
            cout << "select error" << endl;
            break;
        }
        //cout << "press any key to continue......" << endl;
        //getchar();
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
    osip_message_t *ack=NULL;
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
            cout<<"REGISTRATION_FAILURE 收到状态码:"<<osipEventPtr->response->status_code<<"报文"<<endl;
            //cout<<"发送鉴权报文"<<endl;
            //Register();
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
        case EXOSIP_CALL_INVITE:   //收到一个INVITE请求
            printf("a new invite received!\n");
            break;
        case EXOSIP_CALL_REINVITE:   //收到一个REINVITE请求
            printf("REINVITE a new INVITE within call received!\n");
            eXosip_lock ();
            eXosip_call_send_answer (osipEventPtr->tid, 180, NULL);
            eXosip_unlock ();
            eXosip_lock ();
            eXosip_call_send_answer (osipEventPtr->tid, 200, NULL);
            eXosip_unlock ();
            break;
        case EXOSIP_CALL_PROCEEDING: //收到100 trying消息，表示请求正在处理中
            printf("proceeding!\n");
            break;
        case EXOSIP_CALL_RINGING:   //收到180 Ringing应答，表示接收到INVITE请求的UAS正在向被叫用户振铃
            printf("ringing!\n");
            printf("call_id is %d,dialog_id is %d \n",osipEventPtr->cid,osipEventPtr->did);
            break;
        case EXOSIP_CALL_ANSWERED: //收到200 OK，表示请求已经被成功接受，用户应答
            printf("ok!connected!\n");
            callId=osipEventPtr->cid;
            dialogId=osipEventPtr->did;
            printf("call_id is %d,dialog_id is %d \n",osipEventPtr->cid,osipEventPtr->did);

            //回送ack应答消息
            eXosip_call_build_ack(osipEventPtr->did,&ack);
            eXosip_call_send_ack(osipEventPtr->did,ack);
            break;
        case EXOSIP_CALL_ACK: //ACK received for 200ok to INVITE
            printf("ACK received!\n");
            break;
        case EXOSIP_CALL_MESSAGE_ANSWERED:
            printf(" call message answered \n");
            break;        
        case EXOSIP_CALL_CLOSED: //a BYE was received for this call
            printf("the other sid closed!\n");
            break;
        case EXOSIP_CALL_RELEASED:
            printf("call context is cleared.\n");
            callId = -1;
            dialogId = -1;
            break;
        case EXOSIP_MESSAGE_NEW:
            printf("message new \n");
            eXosip_lock ();
            eXosip_call_send_answer (osipEventPtr->did, 200, NULL);
            eXosip_unlock ();
            break;
        case EXOSIP_MESSAGE_ANSWERED:
            printf("message answered \n");
            break;
        default:
            cout << "The sip event type that not be precessed.the event "
                "type is : " << osipEventPtr->type << endl;
            break;
    }
    eXosip_event_free(osipEventPtr);
    return NULL;
}

int main()
{

    char* sConfigFilename = "sip.conf";
    strncpy(sConfig.listenAddr,"61.149.194.174",64);
    strncpy(sConfig.uacPort, "5061", 16);
    sConfig.uacPortInt = 5061;
    strncpy(sConfig.uacCode, "30000025", 64);
    strncpy(sConfig.uacPwd, "123456",64);
    strncpy(sConfig.uasAddr, "47.112.105.194", 46);
    strncpy(sConfig.uasPort, "5060", 16);
    sConfig.expis = 3600;
    readCfg(sConfigFilename,&sConfig);
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
    if (OSIP_SUCCESS != eXosip_listen_addr(IPPROTO_UDP, NULL, sConfig.uacPortInt,
            AF_INET, 0))
    {
        printf("eXosip_listen_addr failure.\n");
        return 1;
    }
    //设置监听网卡
    if (OSIP_SUCCESS != eXosip_set_option(
    EXOSIP_OPT_SET_IPV4_FOR_GATEWAY,
            sConfig.listenAddr))
            // LISTEN_ADDR))
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