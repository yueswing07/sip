/*
 ===============================================================
 GBT28181 ����eXosip2,osip��ʵ��ע��UAC����
 ���ߣ���������
 ���͵�ַ��http://blog.csdn.net/hiwubihe
 QQ��1269122125
 ע��������ԭ�����Ͷ��ɹ�������ѧϰʹ�ã�������ã�Υ�߱ؾ���
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

//���ؼ���IP
#define LISTEN_ADDR ("61.149.194.174")
//���ؼ����˿�
#define UACPORT ("5061")
#define UACPORTINT (5061)
//��UAC��ַ����
#define UACCODE ("30000025")
//����UAC����
#define UACPWD ("123456")
//Զ��UAS IP
#define UAS_ADDR ("47.112.105.194") // 47.112.105.194 192.168.2.251
//Զ��UAS �˿�
#define UAS_PORT ("5060")
//��ʱ
#define EXPIS 3600

//��ǰ����״̬ 1 �Ѿ�ע�� 0 δע��
static int iCurrentStatus;
//ע��ɹ�HANDLE
static int iHandle = -1;

char *pSDP = "v=0\r\n"
                      "o=anonymous 0 0 IN IP4 0.0.0.0\r\n"
                      "t=1 10\r\n"
                      "a=username:rainfish\r\n"
                      "a=password:123\r\n";

enum REGISTER_TYPE{REGISTER,UNREGISTER,REFRESHED};
static REGISTER_TYPE registerType=REGISTER;
/* �÷���һ��ȡ����ipΪ 127.0.0.1 ,windowsҲ����ʹ�ô��෽��,������Ҫ��Ϊ�Ķ�*/
int get_local_ip_using_hostname(char *str_ip) 
{
    int status = -1;
    int i = 0;
    char buf[128] = {0};
    char *local_ip = NULL;
#ifdef WIN32
    WSADATA wsadata;
    if(0 != WSAStartup(MAKEWORD(2, 2), &wsadata))   //��ʼ��
    {
        printf("��ʼ�����绷��ʧ��!");
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

//SIP From/To ͷ��
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
    //��������
    string GetCode()
    {
        std::stringstream stream;
        stream << addrCode;
        return stream.str();
    }
    //������ַ
    string GetAddr()
    {
        std::stringstream stream;
        stream << addrIp;
        return stream.str();
    }
    //�˿�
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

//SIP Contractͷ��
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

//����ע����Ϣ
int SendRegister(int& registerId, CSipFromToHeader &from, CSipFromToHeader &to,
        CContractHeader &contact, const string& userName, const string& pwd,
        const int expires, int iType)
{
    cout << "=============================================" << endl;
    if (iType == 0)
    {
        cout << "ע��������Ϣ��" << endl;
    }
    else if (iType == 1)
    {
        cout << "ˢ��ע����Ϣ��" << endl;
    }
    else
    {
        cout << "ע����Ϣ:" << endl;
    }
    cout << "registerId " << registerId << endl;
    cout << "from " << from.GetFormatHeader() << endl;
    cout << "to " << to.GetFormatHeader() << endl;
    cout << "contact" << contact.GetContractFormatHeader() << endl;
    cout << "userName" << userName << endl;
    cout << "pwd" << pwd << endl;
    cout << "expires" << expires << endl;
    cout << "=============================================" << endl;
    //������ע��
    static osip_message_t *regMsg = 0;
    int ret;

    ::eXosip_add_authentication_info(userName.c_str(), userName.c_str(),
            pwd.c_str(), "MD5", NULL);
    eXosip_lock();
    //����ע����Ϣ 401��Ӧ��eXosip2���Զ�����
    if (0 == registerId)
    {
        // ע����Ϣ�ĳ�ʼ��
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
        // ����ע����Ϣ
        ret = ::eXosip_register_build_register(registerId, expires, &regMsg);
        if (ret != OSIP_SUCCESS)
        {
            return ret;
        }
        //���ע��ԭ��
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
    // ����ע����Ϣ
    ret = ::eXosip_register_send_register(registerId, regMsg);
    if (ret != OSIP_SUCCESS)
    {
        registerId = 0;
    }eXosip_unlock();

    return ret;
}

//ע��
void Register()
{
    if (iCurrentStatus == 1)
    {
        cout << "��ǰ�Ѿ�ע��" << endl;
        return;
    }
	registerType=REFRESHED;
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //����ע����Ϣ
    int registerId = 0;
    if (0 > SendRegister(registerId, stFrom, stTo, stContract, UACCODE, UACPWD,
            3000, 0))
    {
        cout << "����ע��ʧ��" << endl;
        return;
    }
    // iCurrentStatus = 1;
    iHandle = registerId;
}
//ˢ��ע��
void RefreshRegister()
{
    if (iCurrentStatus == 0)
    {
        cout << "��ǰδע�ᣬ������ˢ��" << endl;
        return;
    }
	registerType=REFRESHED;
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //����ע����Ϣ
    if (0 > SendRegister(iHandle, stFrom, stTo, stContract, UACCODE, UACPWD,
            3000, 1))
    {
        cout << "����ˢ��ע��ʧ��" << endl;
        return;
    }
}
//ע��
void UnRegister()
{
    if (iCurrentStatus == 0)
    {
        cout << "��ǰδע�ᣬ������ע��" << endl;
        return;
    }
	registerType=UNREGISTER;
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UACCODE, UAS_ADDR, UAS_PORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //����ע����Ϣ
    if (0 > SendRegister( iHandle, stFrom, stTo, stContract, UACCODE, UACPWD,
            0, 2))
    {
        cout << "����ע��ʧ��" << endl;
        return;
    }
    iCurrentStatus = 0;
    iHandle = -1;
}
// �������
void enterClass(){

}
// �˳�����
void leaveClass()
{
}
// ָ������
void assignInteraction()
{
}
// ȡ������
void cancelInteraction()
{
}
// ����μ�
void shareCourseware()
{
}
// ȡ������μ�
void cancelCourseware()
{
}
// �л���ͷ
void switchCamera()
{
}
static void help()
{
    const char
            *b =
    "-------------------------------------------------------------------------------\n"
    "SIP Library test process - uac v 1.0 (June 13, 2014)\n\n"
    "SIP UAC�� ע��,ˢ��ע��,ע��ʵ��\n\n"
    "Author: ��������\n\n"
    "���͵�ַ:http://blog.csdn.net/hiwubihe QQ:1269122125\n\n"
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
//�������߳�
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
            //ע��
            Register();
            break;
        case '1':
            //ˢ��ע��
            RefreshRegister();
            break;
        case '2':
            //ע��
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

//�¼������߳�
//DWORD WINAPI eventHandle(LPVOID lpParameter)
void *eventHandle(void *pUser)
{
    eXosip_event_t* osipEventPtr = (eXosip_event_t*) pUser;
    switch (osipEventPtr->type)
    {
        //��Ҫ������֤REGISTER��ʲô����
        case EXOSIP_REGISTRATION_SUCCESS:
            cout<<"REGISTRATION_SUCCESS �յ�״̬��:"<<osipEventPtr->response->status_code<<"����"<<endl;
            if(registerType==REFRESHED) 
			iCurrentStatus = 1;
			if(registerType==UNREGISTER) 
			iCurrentStatus = -1;
            break;
        case EXOSIP_REGISTRATION_FAILURE:
            cout<<"REGISTRATION_SUCCESS �յ�״̬��:"<<osipEventPtr->response->status_code<<"����"<<endl;
            cout<<"���ͼ�Ȩ����"<<endl;
            Register();
            break;
		case EXOSIP_REGISTRATION_REFRESHED:
			cout<<"�յ�״̬��:"<<osipEventPtr->response->status_code<<"����"<<endl;
            cout<<"REFRESHED �ɹ�"<<endl;
            break;
		case EXOSIP_REGISTRATION_TERMINATED:
			cout<<"�յ�״̬��:"<<osipEventPtr->response->status_code<<"����"<<endl;
            if(osipEventPtr->response->status_code == 200)
            {
                cout<<"TERMINATED �ɹ�"<<endl;
            }
            else
            {
                cout<<"ע��ʧ��"<<endl;
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
    //�⴦����
    int result = OSIP_SUCCESS;
    //��ʼ����
    if (OSIP_SUCCESS != (result = eXosip_init()))
    {
        printf("eXosip_init failure.\n");
        return 1;
    }
    cout << "eXosip_init success." << endl;
    eXosip_set_user_agent(NULL);
    //����
    if (OSIP_SUCCESS != eXosip_listen_addr(IPPROTO_UDP, NULL, UACPORTINT,
            AF_INET, 0))
    {
        printf("eXosip_listen_addr failure.\n");
        return 1;
    }
    //���ü�������
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
    //���������߳�
    pthread_t pthser;
    if (0 != pthread_create(&pthser, NULL, serverHandle, NULL))
    {
        printf("����������ʧ��\n");
        return -1;
    }
#endif
    //�¼����ڵȴ�
    eXosip_event_t* osipEventPtr = NULL;
    //�����¼�ѭ��
    while (true)
    {
        //�ȴ��¼� 0�ĵ�λ���룬500�Ǻ���
        osipEventPtr = ::eXosip_event_wait(0, 200);
        //����eXosip��Ĭ�ϴ���
        {
            //usleep(500 * 1000);
            eXosip_lock();
            //һ�㴦��401/407���ÿ�Ĭ�ϴ���
            eXosip_default_action(osipEventPtr);
            eXosip_unlock();
        }
        //�¼��ռ����ȴ�
        if (NULL == osipEventPtr)
        {
            continue;
        }
#ifdef _WIN32
        eventHandle(osipEventPtr);
#else
        ////�����̴߳����¼������¼�������Ͻ��¼�ָ���ͷ�
        pthread_t pth;
        if (0 != pthread_create(&pth, NULL, eventHandle, (void*) osipEventPtr))
        {
            printf("�����̴߳����¼�ʧ��\n");
            continue;
        }
#endif
        osipEventPtr = NULL;
    }
}