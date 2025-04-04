//using Microsoft.FSharp.Core;
//using System;
//using System.Collections.Generic;
//using System.Drawing;
//using System.Linq;
//using System.Net;
//using System.Runtime.InteropServices;
//using System.Text;
//using System.Threading;
//using System.Threading.Tasks;
//using static MtkSimalatorSharp.backend.IBackend; 

//namespace MtkSimalatorSharp.backend
//{
//    public class UnicornFSharp : IBackend
//    {
//        UnicornEngine.Unicorn unicorn;

//        public void nativeInitialize(int arch, int mode)
//        {
//            unicorn = new UnicornEngine.Unicorn(arch,mode);
//        } 
//        public BreakPoint AddBreakPoint(long address, IBackend.NativeBreakPointCallback callback, bool thumb)
//        { 
//            throw new NotImplementedException("AddBreakPoint not implemented");
//        }

//        public long ContextAlloc()
//        {
//            throw new NotImplementedException(" not implemented");
//            return 0;
//        }

//        public void ContextFree(long context)
//        {

//            throw new NotImplementedException(" not implemented");
//        }

//        public void ContextRestore(long context)
//        {

//            throw new NotImplementedException(" not implemented");
//        }

//        public void ContextSave(long context)
//        {

//            throw new NotImplementedException(" not implemented");
//        }

//        public void DebuggerAddDebugHook(IBackend.NativeDebugHook callback, object userData, long begin, long end)
//        {

//            throw new NotImplementedException(" not implemented");
//        }

//        public void Destroy()
//        { 
//            throw new NotImplementedException(" not implemented");
//        }

//        public void EmuStart(long begin, long until, long timeout, long count)
//        {
//            unicorn.EmuStart(begin,until,timeout,count);
//        }
//        public void EmuStop()
//        {
//            unicorn.EmuStop();
//        }

//        public void EnableVFP()
//        {
//            // 具体实现取决于Unicorn的API
//            throw new NotImplementedException("EnableVFP not implemented in JNI backend");
//        }

//        public int GetPageSize()
//        {
//            throw new NotImplementedException(" not implemented");
//            // 通常为4096，但可以查询系统或Unicorn获取实际值
//            return 4096;
//        }
         
//        public unsafe void HookAddNewCodeHook(IBackend.NativeCodeHook callback, object userData, long begin, long end)
//        {
//            unicorn.AddCodeHook((a,b,c,d) => {
//                callback(this,b,c,d);
//            }, userData,begin, end);
//        }
         
//        public unsafe void HookAddNewReadHook(IBackend.NativeReadHook callback, object userData, long begin, long end)
//        {
//            unicorn.AddMemReadHook((a, b, c, d) => {
//                callback(this, b, c, d);
//            }, userData, begin, end);
//        }
     
//        public unsafe void HookAddNewBlockHook(IBackend.NativeBlockHook callback, object userData, long begin, long end)
//        {
//            unicorn.AddBlockHook((a, b, c, d) => {
//                callback(this, b, c, d);
//            }, userData, begin, end);
//        }
         
//        public unsafe void HookAddNewWriteHook(IBackend.NativeWriteHook callback, object userData, long begin, long end)
//        { 
//            unicorn.AddMemWriteHook((a, b, c, d,e) => {
//                callback(this, b, c, d,e);
//            }, userData, begin, end);
//        }
          
//        public unsafe void HookAddNewEventMemHook(IBackend.NativeEventMemHook callback, int type, object userData)
//        {
//            unicorn.AddEventMemHook((a, b, c,d,e,f) => {
//                return callback(this, b, c, d, e, f);
//            }, type,userData);
//        }
         
//        public unsafe void HookAddNewInterruptHook(IBackend.NativeInterruptHook callback, object  userData)
//        {
//            unicorn.AddInterruptHook((a, b,c) => {
//                callback(this, b, c);
//            });
//        }

//        public void MemMap(long address, long size, int perms)
//        {
//            unicorn.MemMap(address, size, perms); 
//        }

//        public void MemProtect(long address, long size, int perms)
//        {
//            unicorn.MemProtect(address, size, perms); 
//        }

//        public byte[] MemRead(long address, long size)
//        { 

//            byte[] retdata = new byte[size];
//            unicorn.MemRead(address, retdata);
//            return retdata;
//        }

//        public void MemUnmap(long address, long size)
//        {
//            unicorn.MemUnmap(address, size); 
//        }

//        public void MemWrite(long address, byte[] bytes)
//        { 
//            unicorn.MemWrite(address, bytes); 
//        }

//        public void OnInitialize()
//        {
//            throw new NotImplementedException(" not implemented");
//            // 初始化逻辑已移至构造函数和nativeInitialize方法
//        }

//        public void RegisterEmuCountHook(long emuCount)
//        {

//            throw new NotImplementedException(" not implemented");
//        }

//        public long RegRead(int regId)
//        {
//            return unicorn.RegRead(regId);
//        } 
//        public byte[] RegReadVector(int regId)
//        {
//            throw new NotImplementedException("RegReadVector not implemented");
//        }

//        public void RegWrite(int regId, long value)
//        {

//            unicorn.RegWrite(regId,value);
//        }

//        public void RegWriteVector(int regId, byte[] vector)
//        {

//            throw new NotImplementedException(" not implemented");
//        }

//        public bool RemoveBreakPoint(long address)
//        {

//            throw new NotImplementedException(" not implemented");
//            return false;
//        }

//        public void RemoveJitCodeCache(long begin, long end)
//        {

//            throw new NotImplementedException(" not implemented");
//        }

//        public void SetFastDebug(bool fastDebug)
//        {

//            throw new NotImplementedException(" not implemented");
//        }

//        public void SetSingleStep(int singleStep)
//        {

//            throw new NotImplementedException(" not implemented");
//        } 
//        public void SwitchUserMode()
//        {
//            // 具体实现取决于Unicorn的API
//            throw new NotImplementedException("SwitchUserMode not implemented in JNI backend");
//        } 
//    }
//}
