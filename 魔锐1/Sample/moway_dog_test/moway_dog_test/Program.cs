using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Moway;

namespace moway_dog_test
{
    class Program
    {
        public static string userPIN = "00000000";                 // 出厂默认用户PIN
        public static int ValidateKey()
        {
            UInt32 ret = MowayCS.MW_SUCCESS;
            UInt32 devInfoArraySize = 32;       // 获取设备的最大数量
            MW_DEVICE_INFO_CTX[] devInfoArray = new MW_DEVICE_INFO_CTX[devInfoArraySize];

            UInt32 devCount = 0;
            IntPtr hHandle = IntPtr.Zero;

            //1.枚举锁
            ret = MowayCS.mw_enum(devInfoArray, devInfoArraySize, ref devCount);
            if (ret != MowayCS.MW_SUCCESS)
            {
                Console.WriteLine("mw_enum failed, {0:X8}", ret);
                return -1;
            }

            if (devCount == 0)
            {
                Console.WriteLine("Not found device");
                return -1;
            }

            //2.打开锁
            ret = MowayCS.mw_open(ref devInfoArray[0], MowayCS.MW_OPEN_EXCLUSIVE_MODE, ref hHandle);
            if (ret != MowayCS.MW_SUCCESS)
            {
                Console.WriteLine("mw_open failed, {0:X8}", ret);
                return -1;
            }

            //3.验证用户PIN
            ret = MowayCS.mw_verify_pin(hHandle, Convert.ToByte(MowayCS.MW_PIN_TYPE_USER), Encoding.ASCII.GetBytes(Program.userPIN));
            if (ret == MowayCS.MW_SUCCESS)
            {
                Console.WriteLine("mw_verify_pin success PIN = {0}", Program.userPIN);
            }
            else
            {
                Console.WriteLine("mw_verify_pin failed, {0:X8}", ret);
                MowayCS.mw_close(hHandle);
                return -1;
            }


            //9.关闭锁
            MowayCS.mw_close(hHandle);

            return 1;
        }

        static void Main(string[] args)
        {

            if (ValidateKey() > 0)
            {
                Console.WriteLine("Valid license");
            }
            else
            {
                Console.WriteLine("Invalid license");
            }
            Console.ReadKey();

        }


        


    
    }
}
