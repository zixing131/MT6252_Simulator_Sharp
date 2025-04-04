using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MtkSimalatorSharp.backend
{

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr NewGlobalRefDelegate(IntPtr env, IntPtr obj);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr DeleteGlobalRefDelegate(IntPtr env, IntPtr obj);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate long GetDirectBufferCapacityDelegate(IntPtr env, IntPtr obj); 
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr FindClassDelegate(IntPtr env, string classname);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr ThrowNewDelegate(IntPtr env, IntPtr clz, string data);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr GetByteArrayElementsDelegate(IntPtr env, IntPtr data, IntPtr b);
    //(*env)->ReleaseByteArrayElements(env, bytes, array, JNI_ABORT);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr ReleaseByteArrayElementsDelegate(IntPtr env, IntPtr bytes,IntPtr array, IntPtr b);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int GetArrayLengthDelegate(IntPtr env, IntPtr data);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int RegisterNativesDelegate(IntPtr env, IntPtr classdata, IntPtr s_methods, int len);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int ExceptionCheckDelegate(IntPtr env);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int GetMethodIDDelegate(IntPtr env, IntPtr classdata, string methodname, string signature);

    
    [StructLayout(LayoutKind.Explicit)]
    public struct JNINativeInterface_
    {
        // 保留字段
        [FieldOffset(0x00)] private IntPtr reserved0;
        [FieldOffset(0x08)] private IntPtr reserved1;
        [FieldOffset(0x10)] private IntPtr reserved2;
        [FieldOffset(0x18)] private IntPtr reserved3;

        // 函数指针字段（假设实际偏移）
        [FieldOffset(0x30)] public FindClassDelegate FindClass;
        [FieldOffset(0x70)] public ThrowNewDelegate ThrowNew;
        [FieldOffset(0xA8)] public NewGlobalRefDelegate NewGlobalRef;
        [FieldOffset(0xB0)] public DeleteGlobalRefDelegate DeleteGlobalRef;
        //00000108     jmethodID (*GetMethodID)(JNIEnv *, jclass, const char *, const char *); 
        [FieldOffset(0x108)] public GetMethodIDDelegate GetMethodID;
        //00000558     jsize (*GetArrayLength)(JNIEnv *, jarray); 
        [FieldOffset(0x558)] public GetArrayLengthDelegate GetArrayLength;
        //000005C0 jbyte *(* GetByteArrayElements) (JNIEnv*, jbyteArray, jboolean*);
        [FieldOffset(0x5C0)] public GetByteArrayElementsDelegate GetByteArrayElements;
        // 00000600     void (* ReleaseByteArrayElements) (JNIEnv*, jbyteArray, jbyte*, jint); 
        [FieldOffset(0x600)] public ReleaseByteArrayElementsDelegate ReleaseByteArrayElements;
        //000006B8     jint (*RegisterNatives)(JNIEnv *, jclass, const JNINativeMethod *, jint);
        [FieldOffset(0x6B8)] public RegisterNativesDelegate RegisterNatives;
        //00000720     jboolean(*ExceptionCheck)(JNIEnv*); 
        [FieldOffset(0x720)] public ExceptionCheckDelegate ExceptionCheck;
        [FieldOffset(0x738)] public GetDirectBufferCapacityDelegate GetDirectBufferCapacity;
    }

    //    00000000 struct JNIInvokeInterface // sizeof=0x40
    //00000000 {
    //00000000     void* reserved0;
    //00000008     void* reserved1;
    //00000010     void* reserved2;
    //00000018     jint(*DestroyJavaVM)(JavaVM*);
    //00000020     jint(*AttachCurrentThread)(JavaVM*, JNIEnv**, void*);
    //00000028     jint(*DetachCurrentThread)(JavaVM*);
    //00000030     jint(*GetEnv)(JavaVM*, void**, jint);
    //00000038     jint(*AttachCurrentThreadAsDaemon)(JavaVM*, JNIEnv**, void*);
    //00000040 };


    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int DestroyJavaVMDelegate(IntPtr jvm);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int AttachCurrentThreadDelegate(IntPtr jvm, IntPtr env,IntPtr none);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int DetachCurrentThreadDelegate(IntPtr jvm);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int GetEnvDelegate(IntPtr jvm, ref IntPtr env, int JNI_VERSION_1_6);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int AttachCurrentThreadAsDaemonDelegate(IntPtr jvm, IntPtr data);

    [StructLayout(LayoutKind.Explicit)]
    public struct JNIInvokeInterface
    {
        // 保留字段
        [FieldOffset(0x00)] private IntPtr reserved0;
        [FieldOffset(0x08)] private IntPtr reserved1;
        [FieldOffset(0x10)] private IntPtr reserved2;
        [FieldOffset(0x18)] public DestroyJavaVMDelegate DestroyJavaVM;
        [FieldOffset(0x20)] public AttachCurrentThreadDelegate AttachCurrentThread;
        [FieldOffset(0x28)] public DetachCurrentThreadDelegate DetachCurrentThread;
        [FieldOffset(0x30)] public GetEnvDelegate GetEnv;
        [FieldOffset(0x38)] public AttachCurrentThreadAsDaemonDelegate AttachCurrentThreadAsDaemon;
          
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct JNIEnv
    {
        public IntPtr functions; // 指向 JNINativeInterface_ 的指针
    } 



    /// <summary>
    /// maybe is a jbytes
    /// </summary>

    public struct Jbytes
    {
        public int size;
        public byte[] data;

        public Jbytes(byte[] datain)
        {
            this.data = datain;
            this.size = datain.Length;
        } 
        /// <summary>
        /// 从 IntPtr 还原 Jbytes（非托管内存指针 -> 托管结构体）
        /// </summary>
        public static Jbytes FromIntPtr(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                throw new ArgumentNullException(nameof(ptr), "指针不能为 IntPtr.Zero");

            // 读取 size（前 4 字节）
            int size = Marshal.ReadInt32(ptr, 0);

            if (size < 0)
                throw new InvalidOperationException("非托管数据中的 size 字段为负数");

            // 读取 data（后续字节）
            byte[] data = new byte[size];
            if (size > 0)
            {
                Marshal.Copy(ptr + 4, data, 0, size);
            }

            return new Jbytes(data);
        }


        public IntPtr ToIntPtr()
        {
            // 分配非托管内存：4 字节（size） + data 长度
            IntPtr ptr = Marshal.AllocHGlobal(4 + size); 
            try
            {
                // 写入 size（前 4 字节）
                Marshal.WriteInt32(ptr, 0, size);

                // 写入 data（后续字节）
                if (size > 0)
                {
                    Marshal.Copy(data, 0, ptr + 4, size);
                } 
                return ptr;
            }
            catch
            {
                // 失败时释放内存
                Marshal.FreeHGlobal(ptr);
                throw;
            } 
        } 
    } 

    /// <summary>
    /// Jobject载体，实际上托载了一个函数
    /// </summary>
    public struct Jobject
    {
        NewHook newhook;
        public Jobject(NewHook newhook)
        {
            this.newhook = newhook;
        }

        /// <summary>
        /// 从 IntPtr 还原 Jobject（非托管内存指针 -> 托管结构体）
        /// </summary>
        public static Jobject FromIntPtr(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return default(Jobject);

            // 从指针位置读取结构体
            return Marshal.PtrToStructure<Jobject>(ptr);
        }

        /// <summary>
        /// 将 Jobject 转换为 IntPtr（托管结构体 -> 非托管内存指针）
        /// </summary>
        public IntPtr ToIntPtr()
        {
            // 分配非托管内存
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(this));

            // 将结构体复制到非托管内存
            Marshal.StructureToPtr(this, ptr, false);

            return ptr;
        }

        // 可选：释放非托管内存的方法
        public static void FreeIntPtr(IntPtr ptr)
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }


    public class JniSim
    {

        public const int JNI_OK = 0;
        public const int JNI_ERR = -1;

        // 静态保存委托防止被 GC 回收
        private static readonly NewGlobalRefDelegate _newGlobalRefImpl = NewGlobalRefImpl;
        private static readonly FindClassDelegate _newFindClassImpl = NewFindClassImpl;

        private static nint NewFindClassImpl(nint env, string classname)
        {
            Console.WriteLine("NewFindClassImpl Enter " + classname);
            return IntPtr.Zero;
        }

        private static readonly ThrowNewDelegate _newThrowNewImpl = ThrowNewImpl;

        private static nint ThrowNewImpl(nint env, nint clz, string data)
        {
            Console.WriteLine("ThrowNewImpl Enter");
            return IntPtr.Zero;
        }

        private static readonly DeleteGlobalRefDelegate _newDeleteGlobalRefImpl = DeleteGlobalRefImpl;

        private static nint DeleteGlobalRefImpl(nint env, nint obj)
        {
            Console.WriteLine("DeleteGlobalRefImpl Enter");
            return IntPtr.Zero;
        }


        private static readonly GetByteArrayElementsDelegate _newGetByteArrayElementsImpl = NewGetByteArrayElementsImpl;
        // NewGlobalRef 的具体实现
        private static IntPtr NewGetByteArrayElementsImpl(IntPtr env, IntPtr data,IntPtr b)
        {
            Console.WriteLine("NewGetByteArrayElementsImpl Enter");
            Jbytes bytes = Jbytes.FromIntPtr(data);
            // 分配非托管内存（需手动释放）
            IntPtr ptr = Marshal.AllocHGlobal(bytes.size);

            try
            {
                // 复制数据到非托管内存
                Marshal.Copy(bytes.data, 0, ptr, bytes.size);

                // 使用 ptr 与非托管代码交互...
                // 示例：调用一个需要 IntPtr 参数的 API
                // NativeMethods.SomeUnmanagedFunction(ptr);
            }
            finally
            {
                // 必须手动释放内存，否则内存泄漏！
                //Marshal.FreeHGlobal(ptr);
            }
            return ptr;
        }


        private static readonly GetArrayLengthDelegate _newGetArrayLengthImpl = NewGetArrayLengthImpl;
        private static readonly ReleaseByteArrayElementsDelegate _newReleaseByteArrayElementsImpl = NewReleaseByteArrayElementsImpl;

        private static nint NewReleaseByteArrayElementsImpl(nint env, nint bytes, nint array, nint b)
        { 
            Console.WriteLine("NewReleaseByteArrayElementsImpl Enter");

            Marshal.FreeHGlobal(bytes);
            Marshal.FreeHGlobal(array);

            return IntPtr.Zero;
        } 

        // NewGlobalRef 的具体实现
        private static IntPtr NewGlobalRefImpl(IntPtr env, IntPtr obj)
        {
            Console.WriteLine("NewGlobalRefImpl Called");
            if (obj == IntPtr.Zero) return IntPtr.Zero;
            GCHandle handle = GCHandle.Alloc(GCHandle.FromIntPtr(obj).Target);
            return GCHandle.ToIntPtr(handle);
        }
        private static readonly GetEnvDelegate _newGetEnvImpl = GetEnvImpl;

        private static int GetEnvImpl(IntPtr jvm,ref IntPtr env, int JNI_VERSION_1_6)
        { 
            Console.WriteLine("GetEnvImpl Called");

            JNIEnv jnienv = new JNIEnv();

            jnienv.functions = globaljnienv;
            // 3. 将修改后的结构体写回指针
            // 分配非托管内存
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(jnienv));

            // 将结构体复制到非托管内存
            Marshal.StructureToPtr(jnienv, ptr, false);

            env = ptr;
            //Marshal.StructureToPtr(jnienv, env, false); // false = 不释放旧内存

            return JNI_OK;
        }
        static IntPtr globaljnienv;
        public static IntPtr CreateMiniJvm()
        {
            var jvm = new JNIInvokeInterface();
            jvm.GetEnv = _newGetEnvImpl;

            // 将函数表分配到非托管内存
            IntPtr jniFunctionsPtr = Marshal.AllocHGlobal(Marshal.SizeOf<JNIInvokeInterface>());
            Marshal.StructureToPtr(jvm, jniFunctionsPtr, false);

            // 创建 JNIEnv 实例（指向函数表）
            JNIEnv jniEnv = new JNIEnv { functions = jniFunctionsPtr };

            // 将 JNIEnv 实例分配到非托管内存（模拟 JNIEnv*）
            IntPtr jniEnvPtr = Marshal.AllocHGlobal(Marshal.SizeOf<JNIEnv>());
            Marshal.StructureToPtr(jniEnv, jniEnvPtr, false);
            return jniEnvPtr;


        }

        private static readonly RegisterNativesDelegate _newRegisterNativesImpl = RegisterNativesImpl;

        private static int RegisterNativesImpl(IntPtr env, IntPtr classdata, IntPtr s_methods, int len)
        {
            Console.WriteLine("RegisterNativesImpl Called");
            return JNI_OK;
        }

        private static readonly ExceptionCheckDelegate _newExceptionCheckImpl = ExceptionCheckImpl;

        private static int ExceptionCheckImpl(IntPtr env)
        {
            Console.WriteLine("ExceptionCheckImpl Called");
            return JNI_OK;
        }
        private static readonly GetMethodIDDelegate _newGetMethodIDImpl = GetMethodIDImpl;

        private static int GetMethodIDImpl(IntPtr env, IntPtr classdata, string methodname, string signature)
        {
            Console.WriteLine("GetMethodIDImpl Called " + methodname + " " + signature);
            return JNI_OK;
        }

        // 创建精简的 JNIEnv 实例
        public static IntPtr CreateMiniJNIEnv()
        {
            var env = new JNINativeInterface_();
            env.NewGlobalRef = _newGlobalRefImpl;
            env.ThrowNew = _newThrowNewImpl;
            env.DeleteGlobalRef = _newDeleteGlobalRefImpl;
            env.FindClass = _newFindClassImpl;
            env.GetByteArrayElements = _newGetByteArrayElementsImpl;
            env.GetArrayLength = _newGetArrayLengthImpl;
            env.ReleaseByteArrayElements = _newReleaseByteArrayElementsImpl;
            env.RegisterNatives = _newRegisterNativesImpl;
            env.ExceptionCheck = _newExceptionCheckImpl;
            env.ExceptionCheck = _newExceptionCheckImpl;
            env.GetMethodID = _newGetMethodIDImpl;
            

            // 将函数表分配到非托管内存
            IntPtr jniFunctionsPtr = Marshal.AllocHGlobal(Marshal.SizeOf<JNINativeInterface_>());
            Marshal.StructureToPtr(env, jniFunctionsPtr, false);
            globaljnienv = jniFunctionsPtr;

            // 创建 JNIEnv 实例（指向函数表）
            JNIEnv jniEnv = new JNIEnv { functions = jniFunctionsPtr };

            // 将 JNIEnv 实例分配到非托管内存（模拟 JNIEnv*）
            IntPtr jniEnvPtr = Marshal.AllocHGlobal(Marshal.SizeOf<JNIEnv>());
            Marshal.StructureToPtr(jniEnv, jniEnvPtr, false);
            return jniEnvPtr;
        }
         
        private static int NewGetArrayLengthImpl(IntPtr env, IntPtr data)
        {
            Console.WriteLine("NewGetArrayLengthImpl Called");
            Jbytes bytes = Jbytes.FromIntPtr(data);

            return bytes.size;
        } 
    }


    //00000000 struct JNINativeInterface // sizeof=0x740
    //00000000 {
    //00000000     void* reserved0;
    //00000008     void* reserved1;
    //00000010     void* reserved2;
    //00000018     void* reserved3;
    //00000020     jint(*GetVersion)(JNIEnv*);
    //00000028     jclass(*DefineClass)(JNIEnv*, const char*, jobject, const jbyte*, jsize);
    //00000030     jclass(*FindClass)(JNIEnv*, const char*);
    //00000038     jmethodID(*FromReflectedMethod)(JNIEnv*, jobject);
    //00000040     jfieldID(*FromReflectedField)(JNIEnv*, jobject);
    //00000048     jobject(*ToReflectedMethod)(JNIEnv*, jclass, jmethodID, jboolean);
    //00000050     jclass(*GetSuperclass)(JNIEnv*, jclass);
    //00000058     jboolean(*IsAssignableFrom)(JNIEnv*, jclass, jclass);
    //00000060     jobject(*ToReflectedField)(JNIEnv*, jclass, jfieldID, jboolean);
    //00000068     jint(*Throw)(JNIEnv*, jthrowable);
    //00000070     jint(*ThrowNew)(JNIEnv*, jclass, const char*);
    //00000078     jthrowable(*ExceptionOccurred)(JNIEnv*);
    //00000080     void (* ExceptionDescribe) (JNIEnv*);
    //00000088     void (* ExceptionClear) (JNIEnv*);
    //00000090     void (* FatalError) (JNIEnv*, const char*);
    //00000098     jint(*PushLocalFrame)(JNIEnv*, jint);
    //000000A0 jobject(*PopLocalFrame)(JNIEnv*, jobject);
    //000000A8 jobject(*NewGlobalRef)(JNIEnv*, jobject);
    //000000B0 void (* DeleteGlobalRef) (JNIEnv*, jobject);
    //000000B8 void (* DeleteLocalRef) (JNIEnv*, jobject);
    //000000C0 jboolean(*IsSameObject)(JNIEnv*, jobject, jobject);
    //000000C8 jobject(*NewLocalRef)(JNIEnv*, jobject);
    //000000D0     jint(*EnsureLocalCapacity)(JNIEnv*, jint);
    //000000D8     jobject(*AllocObject)(JNIEnv*, jclass);
    //000000E0     jobject(*NewObject)(JNIEnv*, jclass, jmethodID, ...);
    //000000E8     jobject(*NewObjectV)(JNIEnv*, jclass, jmethodID, va_list);
    //000000F0     jobject(*NewObjectA)(JNIEnv*, jclass, jmethodID, jvalue*);
    //000000F8     jclass(*GetObjectClass)(JNIEnv*, jobject);
    //00000100     jboolean(*IsInstanceOf)(JNIEnv*, jobject, jclass);
    //00000108     jmethodID(*GetMethodID)(JNIEnv*, jclass, const char*, const char*);
    //00000110     jobject(*CallObjectMethod)(JNIEnv*, jobject, jmethodID, ...);
    //00000118     jobject(*CallObjectMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    //00000120     jobject(*CallObjectMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    //00000128     jboolean(*CallBooleanMethod)(JNIEnv*, jobject, jmethodID, ...);
    //00000130     jboolean(*CallBooleanMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    //00000138     jboolean(*CallBooleanMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    //00000140     jbyte(*CallByteMethod)(JNIEnv*, jobject, jmethodID, ...);
    //00000148     jbyte(*CallByteMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    //00000150     jbyte(*CallByteMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    //00000158     jchar(*CallCharMethod)(JNIEnv*, jobject, jmethodID, ...);
    //00000160     jchar(*CallCharMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    //00000168     jchar(*CallCharMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    //00000170     jshort(*CallShortMethod)(JNIEnv*, jobject, jmethodID, ...);
    //00000178     jshort(*CallShortMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    //00000180     jshort(*CallShortMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    //00000188     jint(*CallIntMethod)(JNIEnv*, jobject, jmethodID, ...);
    //00000190     jint(*CallIntMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    //00000198     jint(*CallIntMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    //000001A0 jlong(*CallLongMethod)(JNIEnv*, jobject, jmethodID, ...);
    //000001A8 jlong(*CallLongMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    //000001B0 jlong(*CallLongMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    //000001B8 jfloat(*CallFloatMethod)(JNIEnv*, jobject, jmethodID, ...);
    //000001C0 jfloat(*CallFloatMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    //000001C8 jfloat(*CallFloatMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    //000001D0     jdouble(*CallDoubleMethod)(JNIEnv*, jobject, jmethodID, ...);
    //000001D8     jdouble(*CallDoubleMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    //000001E0     jdouble(*CallDoubleMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    //000001E8     void (* CallVoidMethod) (JNIEnv*, jobject, jmethodID, ...);
    //000001F0     void (* CallVoidMethodV) (JNIEnv*, jobject, jmethodID, va_list);
    //000001F8     void (* CallVoidMethodA) (JNIEnv*, jobject, jmethodID, jvalue*);

}
