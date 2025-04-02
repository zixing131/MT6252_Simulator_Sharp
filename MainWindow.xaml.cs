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
using System.Windows.Navigation;
using System.Windows.Shapes;

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
    private ImageSource ToBitmapSourceA(Bitmap bitmap)
    {
        MemoryStream stream = new MemoryStream();
        bitmap.Save(stream, ImageFormat.Bmp);
        stream.Position = 0;
        BitmapImage bitmapImage = new BitmapImage();
        bitmapImage.BeginInit();
        bitmapImage.StreamSource = stream;
        bitmapImage.EndInit();
        return bitmapImage;
    }

    void UpdateSurfaceAction(Bitmap bitmap)
    {
        //Console.WriteLine("bitmap " + bitmap);
        myscreen.Dispatcher.Invoke(() =>
        {
            //Convert it to BitmapImage 
            myscreen.Source = ToBitmapSourceA(bitmap); 
        });   
    } 
} 