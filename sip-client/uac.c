#include <eXosip2/eXosip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
//#include <netinet/in.h>
#include <winsock2.h>

int main(int argc,char *argv[])
{

    struct eXosip_t *context_eXosip;

    eXosip_event_t *je;
    osip_message_t *reg=NULL;
    osip_message_t *invite=NULL;
    osip_message_t *ack=NULL;
    osip_message_t *info=NULL;
    osip_message_t *message=NULL;

    int call_id,dialog_id;
    int i,flag;
    int flag1=1;
	int registerId = 0;	

    char *identity="sip:123.56.69.66:15061";   //UAC1，端口是15060
    //char *registar="sip:133@192.168.2.251:15061"; //UAS,端口是15061
    char *registar="sip:30000025@47.112.105.194:5060"; //UAS,端口是15061
    char *source_call="sip:30000025@123.56.69.66:15061";
    char *dest_call="sip:47.112.105.194:5060";

    //identify和register这一组地址是和source和destination地址相同的
    //在这个例子中，uac和uas通信，则source就是自己的地址，而目的地址就是uac1的地址
    char command;
    char tmp[4096];

	identity="sip:100110000201000000@192.168.2.103:15060";   //UAC1，端口是15060
    //char *registar="sip:133@192.168.2.251:15061"; //UAS,端口是15061
    registar="sip:100110000201000000@192.168.2.251:5060"; //UAS,端口是15061
    source_call="sip:100110000201000000@192.168.2.103:15060";
    dest_call="sip:100110000201000000@192.168.2.251:5060";

    printf("r   向服务器注册\n\n");
    printf("c   取消注册\n\n");
    printf("i   发起呼叫请求\n\n");
    printf("h   挂断\n\n");
    printf("q   推出程序\n\n");
    printf("s   执行方法INFO\n\n");
    printf("m   执行方法MESSAGE\n\n");

    //初始化
    i=eXosip_init();

    if(i!=OSIP_SUCCESS )
    {
        printf("Couldn't initialize eXosip!\n");
        return -1;
    }
    else
    {
        printf("eXosip_init successfully!\n");
    }

    //绑定uac自己的端口15060，并进行端口监听
    i=eXosip_listen_addr(IPPROTO_UDP,NULL,15060,AF_INET,0);
    if(i!=0)
    {
        eXosip_quit();
        fprintf(stderr,"Couldn't initialize transport layer!\n");
        return -1;
    }

    flag=1;
    while(flag)
    {
        //输入命令
        printf("Please input the command:\n");
        scanf("%c",&command);
        getchar();

        switch(command)
        {
        case 'r':
			registerId = eXosip_register_build_initial_register(dest_call,dest_call,NULL,3600,&reg);
			if(registerId<0) {
				printf(" build initial register error.");
				break;
			}

			eXosip_lock();
            i=eXosip_register_send_register(registerId,reg); //invite SIP INVITE message to send
            eXosip_unlock();

            //发送了INVITE消息，等待应答
            flag1=1;
            while(flag1)
            {
                je=eXosip_event_wait(0,200); //Wait for an eXosip event
                //(超时时间秒，超时时间毫秒)
                if(je==NULL)
                {
                    printf("No response or the time is over!\n");
                    break;
                }
                switch(je->type)   //可能会到来的事件类型
                {
                case EXOSIP_CALL_INVITE:   //收到一个INVITE请求
                    printf("a new invite received!\n");
                    break;
                case EXOSIP_CALL_PROCEEDING: //收到100 trying消息，表示请求正在处理中
                    printf("proceeding!\n");
                    break;
                case EXOSIP_CALL_RINGING:   //收到180 Ringing应答，表示接收到INVITE请求的UAS正在向被叫用户振铃
                    printf("ringing!\n");
                    printf("call_id is %d,dialog_id is %d \n",je->cid,je->did);
                    break;
                case EXOSIP_CALL_ANSWERED: //收到200 OK，表示请求已经被成功接受，用户应答
                    printf("ok!connected!\n");
                    call_id=je->cid;
                    dialog_id=je->did;
                    printf("call_id is %d,dialog_id is %d \n",je->cid,je->did);

                    //回送ack应答消息
                    eXosip_call_build_ack(je->did,&ack);
                    eXosip_call_send_ack(je->did,ack);
                    flag1=0; //推出While循环
                    break;
                case EXOSIP_CALL_CLOSED: //a BYE was received for this call
                    printf("the other sid closed!\n");
                    break;
                case EXOSIP_CALL_ACK: //ACK received for 200ok to INVITE
                    printf("ACK received!\n");
                    break;
                default: //收到其他应答
                    printf("other response!\n");
                    break;
                }
                eXosip_event_free(je); //Free ressource in an eXosip event
            }
            break;
        case 'i'://INVITE，发起呼叫请求
            i=eXosip_call_build_initial_invite(&invite,dest_call,source_call,NULL,"This is a call for conversation");
            if(i!=0)
            {
                printf("Initial INVITE failed!\n");
                break;
            }
            //符合SDP格式，其中属性a是自定义格式，也就是说可以存放自己的信息，
            //但是只能有两列，比如帐户信息
            //但是经过测试，格式vot必不可少，原因未知，估计是协议栈在传输时需要检查的
            snprintf(tmp,4096,
                      "v=0\r\n"
                      "o=anonymous 0 0 IN IP4 0.0.0.0\r\n"
                      "t=1 10\r\n"
                      "a=username:rainfish\r\n"
                      "a=password:123\r\n");

            osip_message_set_body(invite,tmp,strlen(tmp));
            osip_message_set_content_type(invite,"application/sdp");

            eXosip_lock();
            i=eXosip_call_send_initial_invite(invite); //invite SIP INVITE message to send
            eXosip_unlock();

            //发送了INVITE消息，等待应答
            flag1=1;
            while(flag1)
            {
                je=eXosip_event_wait(0,200); //Wait for an eXosip event
                //(超时时间秒，超时时间毫秒)
                if(je==NULL)
                {
                    printf("No response or the time is over!\n");
                    break;
                }
                switch(je->type)   //可能会到来的事件类型
                {
                case EXOSIP_CALL_INVITE:   //收到一个INVITE请求
                    printf("a new invite received!\n");
                    break;
                case EXOSIP_CALL_PROCEEDING: //收到100 trying消息，表示请求正在处理中
                    printf("proceeding!\n");
                    break;
                case EXOSIP_CALL_RINGING:   //收到180 Ringing应答，表示接收到INVITE请求的UAS正在向被叫用户振铃
                    printf("ringing!\n");
                    printf("call_id is %d,dialog_id is %d \n",je->cid,je->did);
                    break;
                case EXOSIP_CALL_ANSWERED: //收到200 OK，表示请求已经被成功接受，用户应答
                    printf("ok!connected!\n");
                    call_id=je->cid;
                    dialog_id=je->did;
                    printf("call_id is %d,dialog_id is %d \n",je->cid,je->did);

                    //回送ack应答消息
                    eXosip_call_build_ack(je->did,&ack);
                    eXosip_call_send_ack(je->did,ack);
                    flag1=0; //推出While循环
                    break;
                case EXOSIP_CALL_CLOSED: //a BYE was received for this call
                    printf("the other sid closed!\n");
                    break;
                case EXOSIP_CALL_ACK: //ACK received for 200ok to INVITE
                    printf("ACK received!\n");
                    break;
                default: //收到其他应答
                    printf("other response!\n");
                    break;
                }
                eXosip_event_free(je); //Free ressource in an eXosip event
            }
            break;

        case 'h':   //挂断
            printf("Holded!\n");

            eXosip_lock();
            eXosip_call_terminate(call_id,dialog_id);
            eXosip_unlock();
            break;

        case 'c':
            printf("This modal is not commpleted!\n");
            break;

        case 's': //传输INFO方法
            eXosip_call_build_info(dialog_id,&info);
            snprintf(tmp,4096,"\nThis is a sip message(Method:INFO)");
            osip_message_set_body(info,tmp,strlen(tmp));
            //格式可以任意设定，text/plain代表文本信息;
            osip_message_set_content_type(info,"text/plain");
            eXosip_call_send_request(dialog_id,info);
            break;

        case 'm':
            //传输MESSAGE方法，也就是即时消息，和INFO方法相比，我认为主要区别是：
            //MESSAGE不用建立连接，直接传输信息，而INFO消息必须在建立INVITE的基础上传输
            printf("the method : MESSAGE\n");
            eXosip_message_build_request(&message,"MESSAGE",dest_call,source_call,NULL);
            //内容，方法，      to       ，from      ，route
            snprintf(tmp,4096,"This is a sip message(Method:MESSAGE)");
            osip_message_set_body(message,tmp,strlen(tmp));
            //假设格式是xml
            osip_message_set_content_type(message,"text/xml");
            eXosip_message_send_request(message);
            break;

        case 'q':
            eXosip_quit();
            printf("Exit the setup!\n");
            flag=0;
            break;
        }
    }

    return(0);
}