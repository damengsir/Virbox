using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using SLM_HANDLE_INDEX = System.UInt32;

namespace ValidKey
{
    public delegate uint callback(uint message, UIntPtr wparam, UIntPtr lparam);

    //init struct
    public struct ST_INIT_PARAM
    {
        /** 版本－用来兼容，当前使用 SLM_CALLBACK_VERSION02 */
        public UInt32 version;
        /** 如果需要接收SenseShield服务通知，填 SLM_INIT_FLAG_NOTIFY */
        public UInt32 flag;
        /** 回调函数指针*/
        [MarshalAs(UnmanagedType.FunctionPtr)]
        public callback pfn;

        /** 通信连接超时时间（毫秒），如果填0，则使用默认超时时间（7秒）*/
        public UInt32 timeout;
        /** API密码，可从深思云开发者中心（https://developer.senseyun.com），通过“查看开发商信息”获取*/
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int)SSDefine.SLM_DEV_PASSWORD_LENGTH)]
        public byte[] password;
    }


    /** 设备证书类型*/
    public enum CERT_TYPE : uint
    {
        /** 证书类型：根证书  */
        CERT_TYPE_ROOT_CA = 0,

        /** 证书类型：设备子CA  */
        CERT_TYPE_DEVICE_CA = 1,

        /** 证书类型：设备证书  */
        CERT_TYPE_DEVICE_CERT = 2,

        /** 证书类型：深思设备证书  */
        CERT_TYPE_SENSE_DEVICE_CERT = 3,
    }


    internal class SlmRuntime
    {
        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate UInt32 SSRuntimeCallBack(UInt32 message, IntPtr wparam, IntPtr lparam);
        private static bool Is64 = IntPtr.Size == 8 ? true : false;

#if DEBUG
        // 调试使用可调试的运行时库（允许调试）
        const string dll_name32 = "x86/slm_runtime.dll";
        const string dll_name64 = "x64/slm_runtime.dll";
#else
        // 正式发版，使用具有反调试功能的运行时库（不允许调试）
        const string dll_name32 = "x86/slm_runtime.dll";
        const string dll_name64 = "x64/slm_runtime.dll";
#endif


        /// <summary>
        /// Runtime API初始化函数，调用所有Runtime API必须先调用此函数进行初始化
        /// </summary>
        ///  <param name="init_param"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#1", CallingConvention = CallingConvention.StdCall)]
        internal static extern UInt32 slm_init32(
             ref ST_INIT_PARAM initParam);
        [DllImport(dll_name64, EntryPoint = "#1", CallingConvention = CallingConvention.StdCall)]
        internal static extern UInt32 slm_init64(
             ref ST_INIT_PARAM initParam);

        internal static UInt32 slm_init(
            ref ST_INIT_PARAM initParam)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_init64(ref initParam);
            }
            return SlmRuntime.slm_init32(ref initParam);
        }

        /// <summary>
        /// 列举锁内某id许可
        /// </summary>
        /// <param name="license_id"></param>
        /// <param name="format"></param>
        /// <param name="license_desc"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#2", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_find_license32(
            UInt32 license_id,
            INFO_FORMAT_TYPE format,
            ref IntPtr license_desc);

        [DllImport(dll_name64, EntryPoint = "#2", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_find_license64(
            UInt32 license_id,
            INFO_FORMAT_TYPE format,
            ref IntPtr license_desc);


        internal static UInt32 slm_find_license(
            UInt32 license_id,
            INFO_FORMAT_TYPE format,
            ref IntPtr license_desc)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_find_license64(license_id, format, ref license_desc);
            }
            return SlmRuntime.slm_find_license32(license_id, format, ref license_desc);
        }
		
        /// <summary>
        /// 安全登录许可
        /// </summary>
        /// <param name="license_param"></param>
        /// <param name="param_format"></param>
        /// <param name="slm_handle"></param>
        /// <param name="auth"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#3", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_login32(
            ref ST_LOGIN_PARAM license_param,
            INFO_FORMAT_TYPE param_format,
            ref SLM_HANDLE_INDEX slm_handle,
            IntPtr auth);

        [DllImport(dll_name64, EntryPoint = "#3", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_login64(
            ref ST_LOGIN_PARAM license_param,
            INFO_FORMAT_TYPE param_format,
            ref SLM_HANDLE_INDEX slm_handle,
            IntPtr auth);

        internal static UInt32 slm_login(
            ref ST_LOGIN_PARAM license_param,
            INFO_FORMAT_TYPE param_format,
            ref SLM_HANDLE_INDEX slm_handle,
            IntPtr auth)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_login64(ref license_param, param_format, ref slm_handle, auth);
            }
            return SlmRuntime.slm_login32(ref license_param, param_format, ref slm_handle, auth);
        }
		
        /// <summary>
        /// 枚举已登录的用户token
        /// </summary>
        /// <param name="access_token">默认用户的token，指向一个字符串的IntPtr</param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#4", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_cloud_token32(
            ref IntPtr access_token);

        [DllImport(dll_name64, EntryPoint = "#4", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_cloud_token64(
            ref IntPtr access_token);

        internal static UInt32 slm_get_cloud_token(
            ref IntPtr access_token)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_get_cloud_token64(ref access_token);
            }
            return SlmRuntime.slm_get_cloud_token32(ref access_token);
        }

        /// <summary>
        /// 许可登出，并且释放许可句柄等资源
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#5", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_logout32(
            SLM_HANDLE_INDEX slm_handle);

        [DllImport(dll_name64, EntryPoint = "#5", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_logout64(
            SLM_HANDLE_INDEX slm_handle);

        internal static UInt32 slm_logout(
            SLM_HANDLE_INDEX slm_handle)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_logout64(slm_handle);
            }
            return SlmRuntime.slm_logout32(slm_handle);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#6", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_keep_alive32(
            SLM_HANDLE_INDEX slm_handle);

        [DllImport(dll_name64, EntryPoint = "#6", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_keep_alive64(
            SLM_HANDLE_INDEX slm_handle);

        internal static UInt32 slm_keep_alive(
            SLM_HANDLE_INDEX slm_handle)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_keep_alive64(slm_handle);
            }
            return SlmRuntime.slm_keep_alive32(slm_handle);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="module_id"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#7", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_check_module32(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 module_id);
        [DllImport(dll_name64, EntryPoint = "#7", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_check_module64(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 module_id);

        internal static UInt32 slm_check_module(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 module_id)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_check_module64(slm_handle, module_id);
            }
            return SlmRuntime.slm_check_module32(slm_handle, module_id);
        }	
			
	
        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="inbuffer"></param>
        /// <param name="outbuffer"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#8", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_encrypt32(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
                    [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
                    UInt32 len);

        [DllImport(dll_name64, EntryPoint = "#8", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_encrypt64(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
            UInt32 len);

        internal static UInt32 slm_encrypt(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
            UInt32 len)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_encrypt64(slm_handle, inbuffer, outbuffer, len);
            }
            return SlmRuntime.slm_encrypt32(slm_handle, inbuffer, outbuffer, len);
        }
		
        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="inbuffer"></param>
        /// <param name="outbuffer"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#9", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_decrypt32(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
            UInt32 len);
        [DllImport(dll_name64, EntryPoint = "#9", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_decrypt64(
           SLM_HANDLE_INDEX slm_handle,
           [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
           [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
           UInt32 len);

        internal static UInt32 slm_decrypt(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuffer,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] outbuffer,
            UInt32 len)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_decrypt64(slm_handle, inbuffer, outbuffer, len);
            }
            return SlmRuntime.slm_decrypt32(slm_handle, inbuffer, outbuffer, len);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="type"></param>
        /// <param name="pmem_size"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#10", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_getsize32(
            SLM_HANDLE_INDEX slm_handle,
            LIC_USER_DATA_TYPE type,
            ref UInt32 pmem_size);

        [DllImport(dll_name64, EntryPoint = "#10", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_getsize64(
           SLM_HANDLE_INDEX slm_handle,
           LIC_USER_DATA_TYPE type,
           ref UInt32 pmem_size);

        internal static UInt32 slm_user_data_getsize(
            SLM_HANDLE_INDEX slm_handle,
            LIC_USER_DATA_TYPE type,
            ref UInt32 pmem_size)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_user_data_getsize64(slm_handle, type, ref pmem_size);
            }
            return SlmRuntime.slm_user_data_getsize32(slm_handle, type, ref pmem_size);
        }	
			
        /// <summary>
        /// 读许可数据，可以读取RW和ROM
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="type"></param>
        /// <param name="readbuf"></param>
        /// <param name="offset"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#11", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_read32(
            SLM_HANDLE_INDEX slm_handle,
            LIC_USER_DATA_TYPE type,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
            UInt32 offset,
            UInt32 len);

        [DllImport(dll_name64, EntryPoint = "#11", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_read64(
            SLM_HANDLE_INDEX slm_handle,
            LIC_USER_DATA_TYPE type,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
            UInt32 offset,
            UInt32 len);

        internal static UInt32 slm_user_data_read(
            SLM_HANDLE_INDEX slm_handle,
            LIC_USER_DATA_TYPE type,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
            UInt32 offset,
            UInt32 len)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_user_data_read64(slm_handle, type, readbuf, offset, len);
            }
            return SlmRuntime.slm_user_data_read32(slm_handle, type, readbuf, offset, len);
        }	
		
        /// <summary>
        /// 写许可的读写数据区 ,数据区操作之前请先确认内存区的大小，可以使用slm_user_data_getsize获得
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="writebuf"></param>
        /// <param name="offset"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#12", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_write32(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuf,
            UInt32 offset,
            UInt32 len);
        [DllImport(dll_name64, EntryPoint = "#12", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_user_data_write64(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuf,
            UInt32 offset,
            UInt32 len);

        internal static UInt32 slm_user_data_write(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuf,
            UInt32 offset,
            UInt32 len)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_user_data_write64(slm_handle, writebuf, offset, len);
            }
            return SlmRuntime.slm_user_data_write32(slm_handle, writebuf, offset, len);
        }
       

        /// <summary>
        /// 
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="info_type"></param>
        /// <param name="format"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#13", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_info32(
            SLM_HANDLE_INDEX slm_handle,
            INFO_TYPE info_type,
            INFO_FORMAT_TYPE format,
            ref IntPtr result);
        [DllImport(dll_name64, EntryPoint = "#13", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_info64(
            SLM_HANDLE_INDEX slm_handle,
            INFO_TYPE info_type,
            INFO_FORMAT_TYPE format,
            ref IntPtr result);

        internal static UInt32 slm_get_info(
            SLM_HANDLE_INDEX slm_handle,
            INFO_TYPE info_type,
            INFO_FORMAT_TYPE format,
            ref IntPtr result)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_get_info64(slm_handle, info_type, format, ref result);
            }
            return SlmRuntime.slm_get_info32(slm_handle, info_type, format, ref result);
        }

            

        /// <summary>
        /// 执行锁内算法
        /// </summary>
        /// <param name="slm_handle">许可句柄值</param>
        /// <param name="exfname">锁内执行文件名</param>
        /// <param name="inbuf">输入缓冲区</param>
        /// <param name="insize">输入长度</param>
        /// <param name="poutbuf">输出缓存区</param>
        /// <param name="outsize">输出缓存长度</param>
        /// <param name="pretsize">实际返回缓存长度</param>
        /// <returns>成功返回SS_OK，失败返回相应的错误码</returns>
        [DllImport(dll_name32, EntryPoint = "#14", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_execute_static32(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPTStr)] string exfname,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
            UInt32 insize,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
            UInt32 outsize,
            ref UInt32 pretsize);
        [DllImport(dll_name64, EntryPoint = "#14", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_execute_static64(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPTStr)] string exfname,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
            UInt32 insize,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
            UInt32 outsize,
            ref UInt32 pretsize);


        internal static UInt32 slm_execute_static(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPTStr)] string exfname,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
            UInt32 insize,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
            UInt32 outsize,
            ref UInt32 pretsize)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_execute_static64(slm_handle, exfname, inbuf, insize, poutbuf, outsize, ref pretsize);
            }
            return SlmRuntime.slm_execute_static32(slm_handle, exfname, inbuf, insize, poutbuf, outsize, ref pretsize);
        }

        /// <summary>
        /// 许可动态执行代码，由开发商API gen_dynamic_code生成
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="exf_buffer"></param>
        /// <param name="exf_size"></param>
        /// <param name="inbuf"></param>
        /// <param name="insize"></param>
        /// <param name="poutbuf"></param>
        /// <param name="outsize"></param>
        /// <param name="pretsize"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#15", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_execute_dynamic32(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] exf_buffer,
            UInt32 exf_size,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
            UInt32 insize,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
            UInt32 outsize,
            ref UInt32 pretsize);

        [DllImport(dll_name64, EntryPoint = "#15", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_execute_dynamic64(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] exf_buffer,
            UInt32 exf_size,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
            UInt32 insize,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
            UInt32 outsize,
            ref UInt32 pretsize);

        internal static UInt32 slm_execute_dynamic(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] exf_buffer,
            UInt32 exf_size,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] inbuf,
            UInt32 insize,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] poutbuf,
            UInt32 outsize,
            ref UInt32 pretsize)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_execute_dynamic64(slm_handle, exf_buffer, exf_size, inbuf, insize, poutbuf, outsize, ref pretsize);
            }
            return SlmRuntime.slm_execute_dynamic32(slm_handle, exf_buffer, exf_size, inbuf, insize, poutbuf, outsize, ref pretsize);
        }

        /// <summary>
        /// SS内存托管内存申请
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="size"></param>
        /// <param name="mem_id"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#17", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_alloc32(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 size,
            ref UInt32 mem_id);
        [DllImport(dll_name64, EntryPoint = "#17", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_alloc64(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 size,
            ref UInt32 mem_id);

        internal static UInt32 slm_mem_alloc(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 size,
            ref UInt32 mem_id)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_mem_alloc64(slm_handle, size, ref mem_id);
            }
            return SlmRuntime.slm_mem_alloc32(slm_handle, size, ref mem_id);
        }

        /// <summary>
        /// 释放托管内存
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="mem_id"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#18", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_free32(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id);
        [DllImport(dll_name64, EntryPoint = "#18", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_free64(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id);

        internal static UInt32 slm_mem_free(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_mem_free64(slm_handle, mem_id);
            }
            return SlmRuntime.slm_mem_free32(slm_handle, mem_id);
        }

        /// <summary>
        /// SS内存托管读
        /// </summary>
        /// <param name="slm_handle">许可句柄值</param>
        /// <param name="mem_id">托管内存id</param>
        /// <param name="offset">偏移</param>
        /// <param name="len">长度</param>
        /// <param name="readbuff">缓存</param>
        /// <param name="readlen">返回实际读的长度</param>
        /// <returns>成功返回SS_OK，失败返回相应的错误码</returns>
        [DllImport(dll_name32, EntryPoint = "#19", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_read32(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id,
            UInt32 offset,
            UInt32 len,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
            ref UInt32 readlen);

        [DllImport(dll_name64, EntryPoint = "#19", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_read64(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id,
            UInt32 offset,
            UInt32 len,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
            ref UInt32 readlen);

        internal static UInt32 slm_mem_read(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id,
            UInt32 offset,
            UInt32 len,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
            ref UInt32 readlen)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_mem_read64(slm_handle, mem_id, offset, len, readbuff, ref readlen);
            }
            return SlmRuntime.slm_mem_read32(slm_handle, mem_id, offset, len, readbuff, ref readlen);
        }

        /// <summary>
        /// SS内存托管内存写入
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="mem_id"></param>
        /// <param name="offset"></param>
        /// <param name="len"></param>
        /// <param name="writebuff"></param>
        /// <param name="numberofbyteswritten"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#20", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_write32(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id,
            UInt32 offset,
            UInt32 len,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuff,
            ref UInt32 numberofbyteswritten);
        [DllImport(dll_name64, EntryPoint = "#20", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_mem_write64(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id,
            UInt32 offset,
            UInt32 len,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] writebuff,
            ref UInt32 numberofbyteswritten);

        internal static UInt32 slm_mem_write(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 mem_id,
            UInt32 offset,
            UInt32 len,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] readbuff,
            ref UInt32 readlen)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_mem_write64(slm_handle, mem_id, offset, len, readbuff, ref readlen);
            }
            return SlmRuntime.slm_mem_write32(slm_handle, mem_id, offset, len, readbuff, ref readlen);
        }
       
        /// <summary>
        /// 检测是否正在调试
        /// </summary>
        /// <param name="auth">auth 验证数据(目前填IntPtr.Zero即可）</param>
        /// <returns>SS_UINT32错误码, 返回SS_OK代表未调试</returns>
        [DllImport(dll_name32, EntryPoint = "#21", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_is_debug32(
             IntPtr auth);

        [DllImport(dll_name64, EntryPoint = "#21", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_is_debug64(
            IntPtr auth);

        internal static UInt32 slm_is_debug(
            IntPtr auth)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_is_debug64(auth);
            }
            return SlmRuntime.slm_is_debug32(auth);
        }    

        /// <summary>
        /// 获取锁的设备证书
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="device_cert"></param>
        /// <param name="buff_size"></param>
        /// <param name="return_size"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#22", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_device_cert32(
            SLM_HANDLE_INDEX slm_handle,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] device_cert,
            UInt32 buff_size,
            ref UInt32 return_size);

        [DllImport(dll_name64, EntryPoint = "#22", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_device_cert64(
            SLM_HANDLE_INDEX slm_handle,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] device_cert,
            UInt32 buff_size,
            ref UInt32 return_size);

        internal static UInt32 slm_get_device_cert(
            SLM_HANDLE_INDEX slm_handle,
            [In, Out, MarshalAs(UnmanagedType.LPArray)] byte[] device_cert,
            UInt32 buff_size,
            ref UInt32 return_size)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_get_device_cert64(slm_handle, device_cert, buff_size, ref return_size);
            }
            return SlmRuntime.slm_get_device_cert32(slm_handle, device_cert, buff_size, ref return_size);
        }  
		
        /// <summary>
        /// 设备正版验证
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="verify_data"></param>
        /// <param name="verify_data_size"></param>
        /// <param name="signature"></param>
        /// <param name="signature_buf_size"></param>
        /// <param name="signature_size"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#23", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_sign_by_device32(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] verify_data,
            UInt32 verify_data_size,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 signature_buf_size,
            ref UInt32 signature_size);

        [DllImport(dll_name64, EntryPoint = "#23", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_sign_by_device64(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] verify_data,
            UInt32 verify_data_size,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 signature_buf_size,
            ref UInt32 signature_size);

        internal static UInt32 slm_sign_by_device(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] verify_data,
            UInt32 verify_data_size,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 signature_buf_size,
            ref UInt32 signature_size)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_sign_by_device64(slm_handle, verify_data, verify_data_size, signature, signature_buf_size, ref signature_size);
            }
            return SlmRuntime.slm_sign_by_device32(slm_handle, verify_data, verify_data_size, signature, signature_buf_size, ref signature_size);
        } 
		
		
        /// <summary>
        /// 获取时间修复数据，用于生成时钟校准请求
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="rand"></param>
        /// <param name="lock_time"></param>
        /// <param name="pc_time"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#24", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_adjust_time_request32(
            SLM_HANDLE_INDEX slm_handle,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] rand,
            ref UInt32 lock_time,
            ref UInt32 pc_time
            );
        [DllImport(dll_name64, EntryPoint = "#24", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_adjust_time_request64(
            SLM_HANDLE_INDEX slm_handle,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] rand,
            ref UInt32 lock_time,
            ref UInt32 pc_time
            );

        internal static UInt32 slm_adjust_time_request(
            SLM_HANDLE_INDEX slm_handle,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] rand,
            ref UInt32 lock_time,
            ref UInt32 pc_time
            )
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_adjust_time_request64(slm_handle, rand, ref lock_time, ref pc_time);
            }
            return SlmRuntime.slm_adjust_time_request32(slm_handle, rand, ref lock_time, ref pc_time);
        } 


        /// <summary>
        /// 闪烁指示灯
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="led_ctrl"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#25", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_led_control32(
            SLM_HANDLE_INDEX slm_handle,
            ref ST_LED_CONTROL led_ctrl);
        [DllImport(dll_name64, EntryPoint = "#25", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_led_control64(
           SLM_HANDLE_INDEX slm_handle,
           ref ST_LED_CONTROL led_ctrl);

        internal static UInt32 slm_led_control(
            SLM_HANDLE_INDEX slm_handle,
            ref ST_LED_CONTROL led_ctrl)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_led_control64(slm_handle, ref led_ctrl);
            }
            return SlmRuntime.slm_led_control32(slm_handle, ref led_ctrl);
        } 
		

        /// <summary>
        /// 
        /// </summary>
        /// <param name="api_version"></param>
        /// <param name="ss_version"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#26", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_version32(
            ref UInt32 api_version,
            ref UInt32 ss_version);
        [DllImport(dll_name64, EntryPoint = "#26", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_version64(
            ref UInt32 api_version,
            ref UInt32 ss_version);

        internal static UInt32 slm_get_version(
            ref UInt32 api_version,
            ref UInt32 ss_version)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_get_version64(ref api_version, ref ss_version);
            }
            return SlmRuntime.slm_get_version32(ref api_version, ref ss_version);
        } 

        /// <summary>
        /// 升级许可
        /// </summary>
        /// <param name="d2c_pkg">许可D2C数据</param>
        /// <param name="error_msg">错误信息（json）</param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#27", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_update32(
            [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
            ref IntPtr error_msg);

        [DllImport(dll_name64, EntryPoint = "#27", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_update64(
            [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
            ref IntPtr error_msg);

        internal static UInt32 slm_update(
            [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
            ref IntPtr error_msg)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_update64(d2c_pkg, ref error_msg);
            }
            return SlmRuntime.slm_update32(d2c_pkg, ref error_msg);
        } 

        /// <summary>
        ///  将D2C包进行升级
        /// </summary>
        /// <param name="lock_sn"></param>
        /// <param name="d2c_pkg"></param>
        /// <param name="error_msg"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#28", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_update_ex32(
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] lock_sn,
            [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
            ref IntPtr error_msg);

        [DllImport(dll_name64, EntryPoint = "#28", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_update_ex64(
             [In, MarshalAs(UnmanagedType.LPArray)] byte[] lock_sn,
            [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
            ref IntPtr error_msg);

        internal static UInt32 slm_update_ex(
             [In, MarshalAs(UnmanagedType.LPArray)] byte[] lock_sn,
            [In, MarshalAs(UnmanagedType.LPStr)] string d2c_pkg,
            ref IntPtr error_msg)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_update_ex64(lock_sn, d2c_pkg, ref error_msg);
            }
            return SlmRuntime.slm_update_ex32(d2c_pkg, ref error_msg);
        }

        private static uint slm_update_ex32(string d2c_pkg, ref IntPtr error_msg)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        ///  枚举本地锁信息
        /// </summary>
        /// <param name="device_info"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#29", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_enum_device32(
                   ref IntPtr device_info);

        [DllImport(dll_name64, EntryPoint = "#29", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_enum_device64(
          ref IntPtr device_info);

        internal static UInt32 slm_enum_device(
           ref IntPtr device_info)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_enum_device64(ref device_info);
            }
            return SlmRuntime.slm_enum_device32(ref device_info);
        } 

        /// <summary>
        ///   
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#30", CallingConvention = CallingConvention.StdCall)]
        public static extern void slm_free32(IntPtr buffer);

        [DllImport(dll_name64, EntryPoint = "#30", CallingConvention = CallingConvention.StdCall)]
        public static extern void slm_free64(IntPtr buffer);

        internal static void slm_free(IntPtr buffer)
        {
            if (SlmRuntime.Is64)
            {
                SlmRuntime.slm_free64(buffer);
                return;
            }
            SlmRuntime.slm_free32(buffer);
            return;
        } 

        /// <summary>
        ///   获取API对应的开发商ID
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#31", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_developer_id32(
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] buffer);

        [DllImport(dll_name64, EntryPoint = "#31", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_developer_id64(
           [Out, MarshalAs(UnmanagedType.LPArray)] byte[] buffer);

        internal static UInt32 slm_get_developer_id(
           [Out, MarshalAs(UnmanagedType.LPArray)] byte[] buffer)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_get_developer_id64(buffer);
            }
            return SlmRuntime.slm_get_developer_id32(buffer);
        } 

        /// <summary>
        /// 通过错误码获得错误信息
        /// </summary>
        /// <param name="error_code"></param>
        /// <param name="language_id"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#32", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr slm_error_format32(
           UInt32 error_code,
           UInt32 language_id
            );
        [DllImport(dll_name64, EntryPoint = "#32", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr slm_error_format64(
           UInt32 error_code,
           UInt32 language_id
            );

        internal static IntPtr slm_error_format(
           UInt32 error_code,
           UInt32 language_id
            )
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_error_format64(error_code, language_id);
            }
            return SlmRuntime.slm_error_format32(error_code, language_id);
        } 
		
		
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#33", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_cleanup32();

        [DllImport(dll_name64, EntryPoint = "#33", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_cleanup64();

        internal static UInt32 slm_cleanup()
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_cleanup64();
            }
            return SlmRuntime.slm_cleanup32();
        } 


        /// <summary>
        /// 碎片代码执行（开发者不必关心）
        /// </summary>
        /// <param name="slm_handle"></param> 
        /// <param name="snippet_code"></param>
        /// <param name="code_size"></param>
        /// <param name="input"></param>
        /// <param name="input_size"></param>
        /// <param name="output"></param>
        /// <param name="outbuf_size"></param>
        /// <param name="output_size"></param> 
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#35", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_snippet_execute32(
                    SLM_HANDLE_INDEX slm_handle,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] d2c_pkg,
                    UInt32 code_size,
                    [In, MarshalAs(UnmanagedType.LPArray)] byte[] input,
                    UInt32 input_size,
                    [Out, MarshalAs(UnmanagedType.LPArray)] byte[] output,
                    UInt32 outbuf_size,
                    ref UInt32 language_id);
        [DllImport(dll_name64, EntryPoint = "#35", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_snippet_execute64(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] d2c_pkg,
            UInt32 code_size,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] input,
            UInt32 input_size,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] output,
            UInt32 outbuf_size,
            ref UInt32 language_id);

        internal static UInt32 slm_snippet_execute(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] d2c_pkg,
            UInt32 code_size,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] input,
            UInt32 input_size,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] output,
            UInt32 outbuf_size,
            ref UInt32 language_id)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_snippet_execute64(slm_handle, d2c_pkg, code_size, input, input_size, output, outbuf_size, ref language_id);
            }
            return SlmRuntime.slm_snippet_execute32(slm_handle, d2c_pkg, code_size, input, input_size, output, outbuf_size, ref language_id);
        } 


        /// <summary>
        /// 获得指定许可的公开区数据区大小，需要登录0号许可
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="license_id"></param>
        /// <param name="pmem_size"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#36", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_pub_data_getsize32(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 license_id,
            ref UInt32 pmem_size);

        [DllImport(dll_name64, EntryPoint = "#36", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_pub_data_getsize64(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 license_id,
            ref UInt32 pmem_size);

        internal static UInt32 slm_pub_data_getsize(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 license_id,
            ref UInt32 pmem_size)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_pub_data_getsize64(slm_handle, license_id, ref pmem_size);
            }
            return SlmRuntime.slm_pub_data_getsize32(slm_handle, license_id, ref pmem_size);
        } 


        /// <summary>
        /// 获得指定许可的公开区数据区大小，需要登录0号许可
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="license_id"></param>
        /// <param name="readbuf"></param>
        /// <param name="offset"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#37", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_pub_data_read32(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 license_id,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
            UInt32 offset,
            UInt32 len);
        [DllImport(dll_name64, EntryPoint = "#37", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_pub_data_read64(
           SLM_HANDLE_INDEX slm_handle,
           UInt32 license_id,
           [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
           UInt32 offset,
           UInt32 len);

        internal static UInt32 slm_pub_data_read(
            SLM_HANDLE_INDEX slm_handle,
            UInt32 license_id,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] readbuf,
            UInt32 offset,
            UInt32 len)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_pub_data_read64(slm_handle, license_id, readbuf, offset, len);
            }
            return SlmRuntime.slm_pub_data_read32(slm_handle, license_id, readbuf, offset, len);
        } 

        /// <summary>
        /// 锁内短码升级
        /// </summary>
        /// <param name="lock_sn"></param>
        /// <param name="inside_file"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#38", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_d2c_update_inside32(
            [In, MarshalAs(UnmanagedType.LPStr)] string lock_sn,
            [In, MarshalAs(UnmanagedType.LPStr)] string inside_file);

        [DllImport(dll_name64, EntryPoint = "#38", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_d2c_update_inside64(
            [In, MarshalAs(UnmanagedType.LPStr)] string lock_sn,
            [In, MarshalAs(UnmanagedType.LPStr)] string inside_file);

        internal static UInt32 slm_d2c_update_inside(
            [In, MarshalAs(UnmanagedType.LPStr)] string lock_sn,
            [In, MarshalAs(UnmanagedType.LPStr)] string inside_file)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_d2c_update_inside64(lock_sn, inside_file);
            }
            return SlmRuntime.slm_d2c_update_inside32(lock_sn, inside_file);
        } 
		
        /// <summary>
        /// 枚举指定设备下所有许可ID
        /// </summary>
        /// <param name="device_info"></param>
        /// <param name="license_ids"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#39", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_enum_license_id32(
            [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
            ref IntPtr license_ids);
        [DllImport(dll_name64, EntryPoint = "#39", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_enum_license_id64(
           [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
           ref IntPtr license_ids);


        internal static UInt32 slm_enum_license_id(
            [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
            ref IntPtr license_ids)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_enum_license_id64(device_info, ref license_ids);
            }
            return SlmRuntime.slm_enum_license_id32(device_info, ref license_ids);
        } 		
		

        /// <summary>
        /// 枚举指定设备下所有许可ID
        /// </summary>
        /// <param name="device_info"></param>
        /// <param name="license_id"></param>
        /// <param name="license_info"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#40", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_license_info32(
            [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
            UInt32 license_id,
            ref IntPtr license_info);

        [DllImport(dll_name64, EntryPoint = "#40", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_license_info64(
            [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
            UInt32 license_id,
            ref IntPtr license_info);

        internal static UInt32 slm_get_license_info(
            [In, MarshalAs(UnmanagedType.LPStr)] string device_info,
            UInt32 license_id,
            ref IntPtr license_info)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_get_license_info64(device_info, license_id, ref license_info);
            }
            return SlmRuntime.slm_get_license_info32(device_info, license_id, ref license_info);
        } 	


        /// <summary>
        /// 使用已登录的云许可进行签名（仅支持云锁）
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="sign_data"></param>
        /// <param name="sign_length"></param>
        ///  <param name="signature"></param>
        ///   <param name="max_buf_size"></param>
        ///    <param name="signature_length"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#41", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_license_sign32(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
            UInt32 sign_length,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 max_buf_size,
            ref UInt32 signature_length);

        [DllImport(dll_name64, EntryPoint = "#41", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_license_sign64(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
            UInt32 sign_length,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 max_buf_size,
            ref UInt32 signature_length);

        internal static UInt32 slm_license_sign(
            SLM_HANDLE_INDEX slm_handle,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
            UInt32 sign_length,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 max_buf_size,
            ref UInt32 signature_length)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_license_sign64(slm_handle, sign_data, sign_length, signature, max_buf_size, ref signature_length);
            }
            return SlmRuntime.slm_license_sign32(slm_handle, sign_data, sign_length, signature, max_buf_size, ref signature_length);
        } 	
		
		
        /// <summary>
        /// 对云许可签名后的数据进行验签（仅支持云锁）
        /// </summary>
        /// <param name="sign_data"></param>
        /// <param name="sign_length"></param>
        ///  <param name="signature"></param>
        ///   <param name="signature_length"></param>
        ///    <param name="sign_info"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#42", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_license_verify32(
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
            UInt32 sign_length,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 signature_length,
            ref IntPtr sign_info);

        [DllImport(dll_name64, EntryPoint = "#42", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_license_verify64(
           [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
           UInt32 sign_length,
           [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
           UInt32 signature_length,
           ref IntPtr sign_info);

        internal static UInt32 slm_license_verify(
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] sign_data,
            UInt32 sign_length,
            [In, MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            UInt32 signature_length,
            ref IntPtr sign_info)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_license_verify64(sign_data, sign_length, signature, signature_length, ref sign_info);
            }
            return SlmRuntime.slm_license_verify32(sign_data, sign_length, signature, signature_length, ref sign_info);
        } 	

        /// <summary>
        /// 通过证书类型，获取已登录许可的设备证书
        /// </summary>
        /// <param name="slm_handle"></param>
        /// <param name="cert_type"></param>
        ///  <param name="cert"></param>
        ///   <param name="cert_size"></param>
        ///    <param name="cert_len"></param>
        /// <returns></returns>
        [DllImport(dll_name32, EntryPoint = "#43", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_cert32(
            SLM_HANDLE_INDEX slm_handle,
            CERT_TYPE cert_type,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] cert,
            UInt32 cert_size,
            ref UInt32 cert_len);

        [DllImport(dll_name64, EntryPoint = "#43", CallingConvention = CallingConvention.StdCall)]
        public static extern UInt32 slm_get_cert64(
            SLM_HANDLE_INDEX slm_handle,
            CERT_TYPE cert_type,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] cert,
            UInt32 cert_size,
            ref UInt32 cert_len);

        internal static UInt32 slm_get_cert(
            SLM_HANDLE_INDEX slm_handle,
            CERT_TYPE cert_type,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] cert,
            UInt32 cert_size,
            ref UInt32 cert_len)
        {
            if (SlmRuntime.Is64)
            {
                return SlmRuntime.slm_get_cert64(slm_handle, cert_type, cert, cert_size, ref cert_len);
            }
            return SlmRuntime.slm_get_cert32(slm_handle, cert_type, cert, cert_size, ref cert_len);
        }
    }
}
