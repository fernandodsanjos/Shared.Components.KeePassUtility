using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.Collections.Concurrent;

namespace TestKeePassUtility
{
    class Program
    {
        static void Main(string[] args)
        {
           
            Assembly assembly = Assembly.LoadFrom(@"C:\KeePass-2.38\Shared.Components.KeePassUtility.dll");
            Type T = assembly.GetType("KeePassUtility.Utility");
            ConcurrentDictionary<string, KeyValuePair<string, string>> dictionary = null;
            object[] parm = new object[]{ @"\\PAPPASPC\Keys\database.kdbx", @"\\PAPPASPC\Keys\database.key", dictionary};

            // object obj = T.GetMethod("GetEntry").Invoke(null, parm);

           

           T.GetMethod("GetAllEntries").Invoke(null, parm);

            dictionary  = (ConcurrentDictionary<string, KeyValuePair<string, string>>)parm[2];

            foreach (var item in dictionary)
            {
                Console.WriteLine(String.Format("Entry {0}, Key = {1}, Value {2}",item.Key,item.Value.Key, item.Value.Value));
            }

            Console.WriteLine("done");
            Console.ReadKey();

        }
    }
}
