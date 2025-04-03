using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MtkSimalatorSharp.backend
{

    // 定义委托类型（以 NewGlobalRef 为例）
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr NewGlobalRefDelegate(IntPtr env, IntPtr obj);

    // 显式布局结构体（64 位示例）
    [StructLayout(LayoutKind.Explicit, Size = 192)] // 根据实际字段数量调整
    public struct JNINativeInterface_
    {
        // 前导保留字段
        [FieldOffset(0)] private IntPtr reserved0;
        [FieldOffset(8)] private IntPtr reserved1;
        [FieldOffset(16)] private IntPtr reserved2;
        [FieldOffset(24)] private IntPtr reserved3;

        // 函数指针字段（示例：NewGlobalRef 在偏移 144 字节处）
        [FieldOffset(144)]
        public NewGlobalRefDelegate NewGlobalRef;
    }

}
