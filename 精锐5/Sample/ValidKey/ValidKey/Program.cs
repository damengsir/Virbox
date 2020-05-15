using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ValidKey
{

    class Program
    {
        public const int DEVELOPER_ID_LENGTH = 8;
        public const int DEVICE_SN_LENGTH = 16;

        public static void WriteLineGreen(string s)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(s);
            Console.ResetColor();
        }
        public static void WriteLineRed(string s)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(s);
            Console.ResetColor();
        }

        public static byte[] StringToHex(string HexString)
        {
            byte[] returnBytes = new byte[HexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(HexString.Substring(i * 2, 2), 16);

            return returnBytes;
        }

        public static int ValidateKey()
        {
            uint ret = 0;
            string StrMsg = string.Empty;
            IntPtr a = IntPtr.Zero;


            //01. init
            ST_INIT_PARAM initPram = new ST_INIT_PARAM();
            initPram.version = SSDefine.SLM_CALLBACK_VERSION02;
            initPram.flag = SSDefine.SLM_INIT_FLAG_NOTIFY;
            //pfn = new callback(handle_service_msg);     // 响应回调通知只有在 slm_init 后 slm_cleanup 之前有效。
            //initPram.pfn = pfn;

            // 指定开发者 API 密码，示例代码指定 Demo 开发者的 API 密码。
            // 注意：正式开发者运行测试前需要修改此值，可以从 Virbox 开发者网站获取 API 密码。
            initPram.password = StringToHex("A8A5465A1D087CE06D73A9B3E2D78875");

            ret = SlmRuntime.slm_init(ref initPram);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("Slm_Init Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
                return -1;
            }


            //02. find License
            IntPtr desc = IntPtr.Zero;
            ret = SlmRuntime.slm_find_license(1, INFO_FORMAT_TYPE.JSON, ref desc);
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_find_license Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
                return -1;
            }
            else
            {
                SlmRuntime.slm_free(desc);
                if (ret != SSErrCode.SS_OK)
                {
                    StrMsg = string.Format("slm_free Failure:0x{0:X8}", ret);
                    WriteLineRed(StrMsg);
                }
            }

            return 1;
        }
        static void Main(string[] args)
        {

            uint ret = 0;
            string StrMsg = string.Empty;

            if (ValidateKey() > 0)
            {
                //执行操作代码
                WriteLineGreen("Valid License");
            }
            else
            {
                WriteLineRed("Invalid License");
            }


            //22. slm_cleanup
            ret = SlmRuntime.slm_cleanup();
            if (ret != SSErrCode.SS_OK)
            {
                StrMsg = string.Format("slm_cleanup Failure:0x{0:X8}", ret);
                WriteLineRed(StrMsg);
            }
            else
            {
                WriteLineGreen("slm_cleanup Success!");
            }
            Console.ReadKey();
        }
    }
}
