using MT6252_Simulator_Sharp.Simalator;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Security.Policy;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace MT6252_Simulator_Sharp;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        this.Loaded += MainWindow_Loaded;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        MtkLoader();
    }


    private void MtkLoader()
    {
        MtkSimalator.firstEvent = MtkSimalator.VmEventHandleList[0];
        MtkSimalator.initMtkSimalator();


        if (MtkSimalator.MTK != null)
        {
            int size = 0;
            byte[] tmp = null;

            // 读取ROM文件并写入内存
            tmp = MtkSimalator.ReadFile(MtkSimalator.ROM_PROGRAM_BIN, out size);
            MtkSimalator.uc_mem_write(MtkSimalator.MTK, 0x08000000, tmp, size);

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

        // 清理资源
        //MtkSimalator.SD_File_Handle?.Dispose();
        //MtkSimalator.FLASH_File_Handle?.Dispose();
    }
    //private ImageSource ToBitmapSourceA(Bitmap bitmap)
    //{
    //    MemoryStream stream = new MemoryStream();
    //    bitmap.Save(stream, ImageFormat.Bmp);
    //    stream.Position = 0;
    //    BitmapImage bitmapImage = new BitmapImage();
    //    bitmapImage.BeginInit();
    //    bitmapImage.StreamSource = stream;
    //    bitmapImage.EndInit();
    //    return bitmapImage;
    //}

    //void UpdateSurfaceAction(Bitmap bitmap)
    //{
    //    //Console.WriteLine("bitmap " + bitmap);
    //    myscreen.Dispatcher.Invoke(() =>
    //    {
    //        //Convert it to BitmapImage 
    //        myscreen.Source = ToBitmapSourceA(bitmap); 
    //    });   
    //}

    private Bitmap _previousBitmap; // 缓存上一帧的Bitmap

    // 强制转换为 Format32bppArgb
    Bitmap ConvertTo32bppArgb(Bitmap bitmap)
    {
        if (bitmap.PixelFormat == System.Drawing.Imaging.PixelFormat.Format32bppArgb)
            return bitmap;

        var newBitmap = new Bitmap(bitmap.Width, bitmap.Height,
                                 System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(newBitmap))
        {
            g.DrawImage(bitmap, 0, 0);
        }
        return newBitmap;
    }

    void UpdateSurfaceAction(Bitmap newBitmap)
    {
        myscreen.Dispatcher.Invoke(() =>
        {
            if (_previousBitmap == null)
            {
                // 创建新的32bpp位图
                _previousBitmap = new Bitmap(newBitmap.Width, newBitmap.Height,
                                           System.Drawing.Imaging.PixelFormat.Format32bppArgb);
                using (var g = Graphics.FromImage(_previousBitmap))
                {
                    g.DrawImage(newBitmap, 0, 0);
                }
                myscreen.Source = ToBitmapSourceA(_previousBitmap);
            }
            else
            {
                // 确保新位图是32bpp格式
                Bitmap formattedNewBitmap = newBitmap;
                if (newBitmap.PixelFormat != System.Drawing.Imaging.PixelFormat.Format32bppArgb)
                {
                    formattedNewBitmap = new Bitmap(newBitmap.Width, newBitmap.Height,
                                                  System.Drawing.Imaging.PixelFormat.Format32bppArgb);
                    using (var g = Graphics.FromImage(formattedNewBitmap))
                    {
                        g.DrawImage(newBitmap, 0, 0);
                    }
                }

                MergeBitmapWithTransparency(_previousBitmap, formattedNewBitmap);

                // 如果创建了临时位图，需要释放
                if (formattedNewBitmap != newBitmap)
                    formattedNewBitmap.Dispose();

                myscreen.Source = ToBitmapSourceA(_previousBitmap);
            }
        });
    }


    private void MergeBitmapWithTransparency(Bitmap previousBitmap, Bitmap newBitmap)
    {
        // 检查位图是否有效
        if (previousBitmap == null || newBitmap == null)
            throw new ArgumentNullException("Bitmaps cannot be null");

        // 确保两个位图大小相同
        if (previousBitmap.Width != newBitmap.Width || previousBitmap.Height != newBitmap.Height)
            throw new ArgumentException("Bitmaps must have the same dimensions");

        // 确保像素格式是32bppArgb（支持透明度）
        if (previousBitmap.PixelFormat != System.Drawing.Imaging.PixelFormat.Format32bppArgb)
        {
            // 如果不支持透明度，转换为32bppArgb格式
            var temp = new Bitmap(previousBitmap.Width, previousBitmap.Height,
                                System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(temp))
            {
                g.DrawImage(previousBitmap, 0, 0);
            }
            previousBitmap.Dispose(); // 释放原图像
            previousBitmap = temp;
        }

        // 锁定位图数据
        var previousData = previousBitmap.LockBits(
            new Rectangle(0, 0, previousBitmap.Width, previousBitmap.Height),
            ImageLockMode.ReadWrite,
            previousBitmap.PixelFormat);

        var newData = newBitmap.LockBits(
            new Rectangle(0, 0, newBitmap.Width, newBitmap.Height),
            ImageLockMode.ReadOnly,
            newBitmap.PixelFormat);

        try
        {
            unsafe
            {
                byte* prevPtr = (byte*)previousData.Scan0;
                byte* newPtr = (byte*)newData.Scan0;

                for (int y = 0; y < previousBitmap.Height; y++)
                {
                    for (int x = 0; x < previousBitmap.Width; x++)
                    {
                        int index = y * previousData.Stride + x * 4; // 32bpp = 4字节/像素

                        // 检查新图像像素是否非透明（Alpha > 0）且非黑色
                        bool isTransparent = newPtr[index + 3] == 0; // A通道
                        //bool isBlack = newPtr[index] == 0 &&        // B
                        //              newPtr[index + 1] == 0 &&    // G
                        //              newPtr[index + 2] == 0;      // R

                        // 如果新像素不是透明且不是黑色，则覆盖旧像素
                        if (!isTransparent)
                        {
                            prevPtr[index] = newPtr[index];      // B
                            prevPtr[index + 1] = newPtr[index + 1]; // G
                            prevPtr[index + 2] = newPtr[index + 2]; // R
                            prevPtr[index + 3] = newPtr[index + 3]; // A
                        }
                    }
                }
            }
        }
        finally
        {
            previousBitmap.UnlockBits(previousData);
            newBitmap.UnlockBits(newData);
        }
    }

    // 优化的ToBitmapSourceA方法
    private ImageSource ToBitmapSourceA(Bitmap bitmap)
    {
        var bitmapData = bitmap.LockBits(
            new Rectangle(0, 0, bitmap.Width, bitmap.Height),
            ImageLockMode.ReadOnly,
            bitmap.PixelFormat);

        try
        {
            return BitmapSource.Create(
                bitmapData.Width, bitmapData.Height,
                96, 96, // 默认DPI
                PixelFormats.Bgra32, // 使用 BGRA 格式
                null,
                bitmapData.Scan0,
                bitmapData.Stride * bitmapData.Height,
                bitmapData.Stride);
        }
        finally
        {
            bitmap.UnlockBits(bitmapData);
        }
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

       MtkSimalator. EnqueueVMEvent(VM_EVENT.VM_EVENT_KEYBOARD, key, 1);
    }
    private void SimKeyUp(string keycode)
    {

        var key = KeyCodeList[keycode]; 
        MtkSimalator.EnqueueVMEvent(VM_EVENT.VM_EVENT_KEYBOARD, key, 0);
    }


}