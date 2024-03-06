using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Linq;

namespace DarknetHaxor_Aimbot
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            Memory memory = new Memory();

            string[] processNames = { "HD-Player" };
            bool success = memory.SetProcess(processNames);

            if (!success)
            {
                return;
            }
            string scan = "FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A5 43 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";


            IEnumerable<long> addresses = await memory.AoBScan(scan);

            if (addresses.Count() != 0)
            {
                foreach (long address in addresses)
                {

                    string hexString = memory.ReadString(address, scan.Split(' ').Length);
                    string[] hexValuesOld = hexString.Split(' ');

                    string[] hexValues = hexString.Split(' ');
                    Array.Resize(ref hexValues, hexValues.Length - 1);
                    hexString = string.Join(" ", hexValues);


                    string last4Values = string.Join(" ", hexValues.Skip(Math.Max(0, hexValues.Length - 4)));
                    string last8Values = string.Join(" ", hexValues.Skip(Math.Max(0, hexValues.Length - 8)));

                    hexString = hexString.Replace(last8Values, last4Values + " " + last4Values);

                    if ((hexValuesOld[hexValuesOld.Length - 1] == hexValuesOld[hexValuesOld.Length - 9]) && (hexValuesOld[hexValuesOld.Length - 1] == hexValuesOld[hexValuesOld.Length - 5]) && (hexValuesOld[hexValuesOld.Length - 1] == hexValuesOld[hexValuesOld.Length - 13]))
                    {
                        memory.AobReplace(address, hexString);

                    }
                }
            }


            Console.Beep(500, 500);
        }
    }
}
