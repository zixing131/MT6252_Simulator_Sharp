using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static MtkSimalatorSharp.backend.IBackend;

namespace MtkSimalatorSharp.backend
{
    public class UnicornJniNative : IBackend
    {
        private IntPtr _handle;
        private readonly Dictionary<long, BreakPoint> _breakpoints = new Dictionary<long, BreakPoint>();

        public void nativeInitialize(int uC_ARCH_ARM1, int uC_ARCH_ARM2)
        {
            _handle = Java_com_github_unidbg_arm_backend_unicorn_Unicorn_nativeInitialize(IntPtr.Zero, IntPtr.Zero, uC_ARCH_ARM1, uC_ARCH_ARM2);
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to initialize Unicorn backend");
            }
        }

        public BreakPoint AddBreakPoint(long address, NativeBreakPointCallback callback, bool thumb)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_addBreakPoint(IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), address);
            var bp = new BreakPoint(address, callback);
            _breakpoints[address] = bp;
            return bp;
        }

        public long ContextAlloc()
        {
            return Java_com_github_unidbg_arm_backend_unicorn_Unicorn_context_1alloc(IntPtr.Zero, IntPtr.Zero, _handle.ToInt64());
        }

        public void ContextFree(long context)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_free(IntPtr.Zero, IntPtr.Zero, context);
        }

        public void ContextRestore(long context)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_context_1restore(IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), context);
        }

        public void ContextSave(long context)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_context_1save(IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), context);
        }

        public void DebuggerAddDebugHook(IBackend.NativeDebugHook callback, object userData, long begin, long end)
        {
            // 需要实现对应的回调处理
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerDebugger(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), begin, end, IntPtr.Zero);
        }

        public void Destroy()
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_nativeDestroy(IntPtr.Zero, IntPtr.Zero, _handle.ToInt64());
            _handle = IntPtr.Zero;
        }

        public void EmuStart(long begin, long until, long timeout, long count)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_emu_1start(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), begin, until, timeout, count);
        }

        public void EmuStop()
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_emu_1stop(IntPtr.Zero, IntPtr.Zero, _handle.ToInt64());
        }

        public void EnableVFP()
        {
            // 具体实现取决于Unicorn的API
            throw new NotImplementedException("EnableVFP not implemented in JNI backend");
        }

        public int GetPageSize()
        {
            // 通常为4096，但可以查询系统或Unicorn获取实际值
            return 4096;
        }

        private readonly HookManager _hookManager = new();
        public void HookAddNewCodeHook(IBackend.NativeCodeHook callback, object userData, long begin, long end)
        {
            NativeCodeHook nativeHook = (uc, address, size, _) =>
            {
                callback(uc,address, size, userData);
            };

            var hookPtr = _hookManager.RegisterHook(callback, userData, nativeHook);

            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JIJJLcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), 0 /* HOOK_CODE */, begin, end, hookPtr);
        }

        public void HookAddNewReadHook(IBackend.NativeReadHook callback, object userData, long begin, long end)
        {
            NativeReadHook nativeHook = (uc, address, size, _) =>
            {
                callback(uc,address, size, userData);
            };

            var hookPtr = _hookManager.RegisterHook(callback, userData, nativeHook);

            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JIJJLcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), 1 /* HOOK_READ */, begin, end, hookPtr);
        }

        public void HookAddNewBlockHook(IBackend.NativeBlockHook callback, object userData, long begin, long end)
        {
            NativeBlockHook nativeHook = (uc, address, size, userData) =>
            {
                callback(uc, address, size, userData);
            };
            var env = CreateMiniJNIEnv();
            // 将结构体转换为指针
            IntPtr envPtr = Marshal.AllocHGlobal(Marshal.SizeOf(env));
            Marshal.StructureToPtr(env, envPtr, false);

            var hookPtr = _hookManager.RegisterHook(callback, userData, nativeHook);

            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JIJJLcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2(
               envPtr, IntPtr.Zero, _handle.ToInt64(), 1 /* HOOK_READ */, begin, end, hookPtr);
        }
        
        public void HookAddNewWriteHook(IBackend.NativeWriteHook callback, object userData, long begin, long end)
        {
            NativeWriteHook nativeHook = (uc, address, size, value, _) =>
            {
                callback(uc, address, size, value, userData);
            };

            var hookPtr = _hookManager.RegisterHook(callback, userData, nativeHook);

            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JIJJLcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), 2 /* HOOK_WRITE */, begin, end, hookPtr);
        }

        public void HookAddNewEventMemHook(IBackend.NativeEventMemHook callback, int type, object userData)
        {
            NativeEventMemHook nativeHook = (uc, address, size, value, userdata,unmapedtype) =>
            {
                return callback(uc, address, size, value, userdata, unmapedtype);
            };

            var hookPtr = _hookManager.RegisterHook(callback, userData, nativeHook);

            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JILcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), 3 /* HOOK_MEM */, hookPtr);
        }

        // 静态保存委托防止被 GC 回收
        private static readonly NewGlobalRefDelegate _newGlobalRefImpl = NewGlobalRefImpl;

        // 创建精简的 JNIEnv 实例
        public static JNINativeInterface_ CreateMiniJNIEnv()
        {
            var env = new JNINativeInterface_();
            env.NewGlobalRef = _newGlobalRefImpl;
            return env;
        }

        // NewGlobalRef 的具体实现
        private static IntPtr NewGlobalRefImpl(IntPtr env, IntPtr obj)
        {
            Console.WriteLine("NewGlobalRefImpl Called");
            if (obj == IntPtr.Zero) return IntPtr.Zero;
            GCHandle handle = GCHandle.Alloc(GCHandle.FromIntPtr(obj).Target);
            return GCHandle.ToIntPtr(handle);

        }

        public void HookAddNewInterruptHook(IBackend.NativeInterruptHook callback, object userData)
        {
            NativeInterruptHook nativeHook = (uc, intno, _) =>
            {
                callback(uc, intno, userData);
            };

            var hookPtr = _hookManager.RegisterHook(callback, userData, nativeHook);
            var env = CreateMiniJNIEnv();
            // 将结构体转换为指针
            IntPtr envPtr = Marshal.AllocHGlobal(Marshal.SizeOf(env));
            Marshal.StructureToPtr(env, envPtr, false);

            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JILcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2(
                envPtr, IntPtr.Zero, _handle.ToInt64(), 4 /* HOOK_INTR */, hookPtr);
             
            // 使用后释放内存
            //Marshal.FreeHGlobal(envPtr);
        }

        public void MemMap(long address, long size, int perms)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1map(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), address, size, perms);
        }

        public void MemProtect(long address, long size, int perms)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1protect(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), address, size, perms);
        }

        public byte[] MemRead(long address, long size)
        {
            return Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1read(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), address, size);
        }

        public void MemUnmap(long address, long size)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1unmap(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), address, size);
        }

        public void MemWrite(long address, byte[] bytes)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1write(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), address, bytes);
        }

        public void OnInitialize()
        {
            // 初始化逻辑已移至构造函数和nativeInitialize方法
        }

        public void RegisterEmuCountHook(long emuCount)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_register_1emu_1count_1hook(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), emuCount, IntPtr.Zero);
        }

        public long RegRead(int regId)
        {
            return Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1read__JI(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), regId);
        }

        public byte[] RegReadVector(int regId)
        {
            return Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1read__JII(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), regId, 0 /* size? */);
        }

        public void RegWrite(int regId, long value)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1write__JIJ(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), regId, value);
        }

        public void RegWriteVector(int regId, byte[] vector)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1write__JI_3B(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), regId, vector);
        }

        public bool RemoveBreakPoint(long address)
        {
            if (_breakpoints.TryGetValue(address, out var bp))
            {
                Java_com_github_unidbg_arm_backend_unicorn_Unicorn_removeBreakPoint(
                    IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), address);
                _breakpoints.Remove(address);
                return true;
            }
            return false;
        }

        public void RemoveJitCodeCache(long begin, long end)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_removeCache(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), begin, end);
        }

        public void SetFastDebug(bool fastDebug)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_setFastDebug(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), fastDebug);
        }

        public void SetSingleStep(int singleStep)
        {
            Java_com_github_unidbg_arm_backend_unicorn_Unicorn_setSingleStep(
                IntPtr.Zero, IntPtr.Zero, _handle.ToInt64(), singleStep);
        }

        public void SwitchUserMode()
        {
            // 具体实现取决于Unicorn的API
            throw new NotImplementedException("SwitchUserMode not implemented in JNI backend");
        }
        private const string DllName = "unicorn"; // 假设库名称为unicorn.dll或libunicorn.so

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr Java_com_github_unidbg_arm_backend_unicorn_Unicorn_nativeInitialize(IntPtr env, IntPtr clazz, int arg1, int arg2);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_nativeDestroy(IntPtr env, IntPtr clazz, long handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_hook_1del(IntPtr env, IntPtr clazz, long handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern byte[] Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1read__JII(IntPtr env, IntPtr clazz, long handle, int regId, int arg3);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1write__JI_3B(IntPtr env, IntPtr clazz, long handle, int regId, byte[] vector);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1read__JI(IntPtr env, IntPtr clazz, long handle, int regId);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1write__JIJ(IntPtr env, IntPtr clazz, long handle, int regId, long value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Java_com_github_unidbg_arm_backend_unicorn_Unicorn_register_1emu_1count_1hook(IntPtr env, IntPtr clazz, long handle, long emuCount, IntPtr hook);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern byte[] Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1read(IntPtr env, IntPtr clazz, long handle, long address, long size);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1write(IntPtr env, IntPtr clazz, long handle, long address, byte[] bytes);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1map(IntPtr env, IntPtr clazz, long handle, long address, long size, int perms);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1protect(IntPtr env, IntPtr clazz, long handle, long address, long size, int perms);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1unmap(IntPtr env, IntPtr clazz, long handle, long address, long size);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_setFastDebug(IntPtr env, IntPtr clazz, long handle, bool fastDebug);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_setSingleStep(IntPtr env, IntPtr clazz, long handle, int singleStep);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_addBreakPoint(IntPtr env, IntPtr clazz, long handle, long address);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_removeBreakPoint(IntPtr env, IntPtr clazz, long handle, long address);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JIJJLcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2(IntPtr env, IntPtr clazz, long handle, int hookType, long begin, long end, IntPtr hook);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JILcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2(IntPtr env, IntPtr clazz, long handle, int hookType, IntPtr hook);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerDebugger(IntPtr env, IntPtr clazz, long handle, long begin, long end, IntPtr hook);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_emu_1start(IntPtr env, IntPtr clazz, long handle, long begin, long until, long timeout, long count);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_emu_1stop(IntPtr env, IntPtr clazz, long handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long Java_com_github_unidbg_arm_backend_unicorn_Unicorn_context_1alloc(IntPtr env, IntPtr clazz, long handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_free(IntPtr env, IntPtr clazz, long handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_context_1save(IntPtr env, IntPtr clazz, long handle, long context);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_context_1restore(IntPtr env, IntPtr clazz, long handle, long context);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_testSampleArm(IntPtr env, IntPtr clazz);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_testSampleArm64(IntPtr env, IntPtr clazz);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Java_com_github_unidbg_arm_backend_unicorn_Unicorn_removeCache(IntPtr env, IntPtr clazz, long handle, long begin, long end);

    }
}
