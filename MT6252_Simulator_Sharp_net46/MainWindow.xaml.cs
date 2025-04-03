using MT6252_Simulator_Sharp.Simalator;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;

namespace MT6252_Simulator_Sharp
{

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            // 创建 WriteableBitmap
            writeableBmp = new WriteableBitmap(
                MtkSimalator.LCD_SCREEN_WIDTH, MtkSimalator.LCD_SCREEN_HEIGHT, 96, 96,System.Windows.Media.PixelFormats.Bgra32, null);

            myscreen.Source = writeableBmp;

            this.Loaded += MainWindow_Loaded;
        }
        WriteableBitmap writeableBmp;

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            MtkLoader();
        }


        private void MtkLoader()
        {
            MtkSimalator.firstEvent = MtkSimalator.VmEventHandleList[0];
            MtkSimalator.initMtkSimalator();


            if (MtkSimalator.isSuccess())
            {
                //// 分配上下文
                //uc_context_alloc(MTK, out callback_context);
                //uc_context_alloc(MTK, out timer_isr_context);


                // 尝试打开SD卡镜像文件
                try
                {
                    MtkSimalator.SD_File_Handle = File.Open(MtkSimalator.SD_CARD_IMG_PATH, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                }
                catch
                {
                    try
                    {
                        MtkSimalator.SD_File_Handle = File.Open(MtkSimalator.SD_CARD_IMG_PATH, FileMode.Open, FileAccess.Read, FileShare.Read);
                        Console.WriteLine("SD卡镜像文件已被占用，尝试只读方式打开");
                    }
                    catch
                    {
                        Console.WriteLine("没有SD卡镜像文件，跳过加载");
                    }
                }

                /*
                // Flash处理代码（注释保留）
                try 
                {
                    FLASH_File_Handle = File.Open(FLASH_IMG_PATH, FileMode.OpenOrCreate, FileAccess.ReadWrite);

                    byte[] tmp2 = ReadFlashFile(0, 1);
                    if (tmp2[0] == 0)
                    {
                        byte[] tmp3 = new byte[size_1mb];
                        uc_mem_read(MTK, 0x8780000, tmp3, size_1mb);
                        WriteFlashFile(tmp3, 0, size_1mb);
                    }
                    else
                    {
                        byte[] tmp = ReadFlashFile(0, size_1mb);
                        uc_mem_write(MTK, 0x8780000, tmp, size_1mb);
                    }
                }
                catch
                {
                    Console.WriteLine("没有Flash数据文件，跳过加载");
                }
                */

                // 设置控制台缓冲区（C#中无直接等效，可能需要调用Windows API）
                //Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = false });

                MtkSimalator.UpdateSurfaceAction = UpdateSurfaceAction;
                // 启动模拟器线程
                Thread emuThread = new Thread(() => MtkSimalator.RunArmProgram(0x8000000));
                emuThread.Start();

                Thread screenRenderThread = new Thread(() => MtkSimalator.ScreenRenderThread());
                screenRenderThread.Start();

                Console.WriteLine("Unicorn Engine 初始化成功！！");
            }
             
        } 

        void UpdateSurfaceAction(byte[][] datas)
        {

            // 准备一个BGRA格式的字节数组
            byte[] pixelData = new byte[MtkSimalator.LCD_SCREEN_WIDTH * MtkSimalator.LCD_SCREEN_HEIGHT * 4];
            // 先读取当前WriteableBitmap的内容（保留原有像素）
            writeableBmp.Dispatcher.Invoke(() => { 
                writeableBmp.CopyPixels(pixelData, MtkSimalator.LCD_SCREEN_WIDTH * 4, 0); 
            });
            for (byte li = 0; li < 4; li++)
            {
                var screenBuffer = datas[li];
                uint pz = MtkSimalator.LCD_Layer_Address[li];
                if (pz > 0)
                {
                    if (screenBuffer != null)
                    {
                        // Lock bitmap data for direct access 

                        for (ushort i = 0; i < MtkSimalator.LCD_SCREEN_HEIGHT; i++)
                        {
                            for (ushort j = 0; j < MtkSimalator.LCD_SCREEN_WIDTH; j++)
                            {
                                pz = (uint)(j + i * MtkSimalator.LCD_SCREEN_WIDTH);
                                ushort color = BitConverter.ToUInt16(screenBuffer, (int)pz * 2);
                                if (color != 0x1f)
                                {
                                    // Convert 565 RGB to 888 RGB
                                    byte r = (byte)((color >> 11) & 0x1F);
                                    byte g = (byte)((color >> 5) & 0x3F);
                                    byte b = (byte)(color & 0x1F);

                                    // Scale to 8-bit
                                    r = (byte)(r * 255 / 31);
                                    g = (byte)(g * 255 / 63);
                                    b = (byte)(b * 255 / 31);
                                     
                                    // 填充数组
                                    int index = (i * MtkSimalator.LCD_SCREEN_WIDTH + j) * 4;
                                    pixelData[index] = b;
                                    pixelData[index + 1] = g;
                                    pixelData[index + 2] = r;
                                    pixelData[index + 3] = 255;
                                }
                            }
                        } 
                    }
                }
            }

            writeableBmp.Dispatcher.Invoke(() => {

                // 批量复制到WriteableBitmap
                writeableBmp.WritePixels(
                    new Int32Rect(0, 0, MtkSimalator.LCD_SCREEN_WIDTH, MtkSimalator.LCD_SCREEN_HEIGHT),
                    pixelData,
                    MtkSimalator.LCD_SCREEN_WIDTH * 4,
                    0);
            
            }); 
        } 
        private void Button_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            var tag = (sender as Button)?.Tag.ToString();
            if (string.IsNullOrWhiteSpace(tag) == false)
            {
                SimKeyDown(tag);
            }
        }

        private void Button_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            var tag = (sender as Button)?.Tag.ToString();
            if (string.IsNullOrWhiteSpace(tag) == false)
            {
                SimKeyUp(tag);
            }
        }

        const int MR_MOUSE_DOWN = 1;
        const int MR_MOUSE_UP = 2;
        const int MR_MOUSE_MOVE = 3;
        const int MR_KEY_PRESS = 4;
        const int MR_KEY_RELEASE = 5;


        Dictionary<string, uint> KeyCodeList = new Dictionary<string, uint>()
{
    // 数字键 0-9
    { "0", 0 },
    { "1", 1 },
    { "2", 2 },
    { "3", 3 },
    { "4", 4 },
    { "5", 5 },
    { "6", 6 },
    { "7", 7 },
    { "8", 8 },
    { "9", 9 },
    
    // 方向键和功能键
    { "up", 14 },  // 上
    { "down", 15 },  // 下
    { "left", 16 },  // 左
    { "right", 17 },  // 右
    { "ok", 18 },  // OK
    { "softleft", 20 },  // 左软键
    { "softright", 21 },  // 右软键
    { "call", 22 },  // 拨号键
    { "power", 23 },  // 挂机键
    { "*", 10 },  // *
    { "#", 11 }   // #
};

        private void SimKeyDown(string keycode)
        {
            uint key = KeyCodeList[keycode];

            MtkSimalator.EnqueueVMEvent(VM_EVENT.VM_EVENT_KEYBOARD, key, 1);
        }
        private void SimKeyUp(string keycode)
        {

            var key = KeyCodeList[keycode];
            MtkSimalator.EnqueueVMEvent(VM_EVENT.VM_EVENT_KEYBOARD, key, 0);
        }


    }
}