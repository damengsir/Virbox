
using System;
using System.Text;
using System.Runtime.InteropServices;
using SLM_HANDLE_INDEX = System.UInt32;

namespace SenseShield
{
    /// <summary>
    /// 
    /// </summary>
    internal class Help
    {

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
        public static void WriteLineYellow(string s)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(s);
            Console.ResetColor();
        }
        public static void WriteLineBlue(string s)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
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
        public static void hexWriteLine(byte[] buf)
        {
            int i =0;
        
            for (i = 0; i < buf.Length; i++)
            {
                Console.Write("{0:X2} ", buf[i]);
                if (i % 16 == 15)
                {
                    Console.WriteLine();
                }

            }
            Console.WriteLine();
            return;
        }


        /** HEXDUMPº¯Êý */
        /*
        hex_view = 4096 bytes
        offset 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 
        0000 | ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? | ................
        0001 | ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? | ................
        0002 | ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? | ................
        0003 | ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? | ................
        0004 | ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? | ................
        0005 | ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? | ................
        0006 | ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? | ................
        */
        public static void hexall(byte[] buff)
        {
            int i = 0, j = 0;
            int cur = 0;
            int linemax = 0;
            int nprinted = 0;
            Boolean flag = false;
            int len = buff.Length;
            Char[] chars;
            if (0 == len)
            {
                return;
            }
            //UTF8Encoding utf8 = new UTF8Encoding();
            ASCIIEncoding asiic = new ASCIIEncoding();
            int charCount = asiic.GetCharCount(buff);
            chars = new Char[charCount];
            int charsDecodedCount = asiic.GetChars(buff, 0, len, chars, 0);

            Console.Write("hex_view = {0:d} bytes\r\noffset 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", len); Console.WriteLine();
            i = 0; j = 0; flag = true;
            do
            {
                Console.Write("{0:X4} | ", (nprinted / 16));
                if (nprinted >= len)
                {
                    flag = false;
                    break;
                }
                linemax = 16;
                for (j = 0; j < linemax; j++)
                {
                    cur = i + j;
                    if (cur >= len)
                    {
                        flag = false;
                        Console.Write("   ");
                    }
                    else
                    {
                        Console.Write("{0:X2} ", buff[cur]);
                        nprinted++;
                    }
                }
                Console.Write("| ");
                for (j = 0; j < linemax; j++)
                {
                    cur = i + j;
                    if (cur >= len)
                    {
                        flag = false;
                        break;
                    }
                    if (buff[cur] > 30 && buff[cur] < 127)
                    { //Console.Write("{0:c}", buff[cur]);

                        Console.Write("{0}", chars[cur]);
                        //Console.Write(buff[cur].ToString);
                    }
                    else
                    { Console.Write("."); }
                }
                i += 16;
                Console.WriteLine();
            } while (flag);
            Console.WriteLine();
            return;
        }

    }
}