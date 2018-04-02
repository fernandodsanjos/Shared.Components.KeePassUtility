using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using KeePass.App;
using KeePass.Forms;
using KeePass.Util;
using KeePass.UI;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Utility;
using KeePassLib;
using System.Collections.Concurrent;

namespace KeePassUtility
{
    public static class Utility
    {
        public static void GetAllEntries(string databasefile, string keyfile, out ConcurrentDictionary<string, KeyValuePair<string, string>> dictionary)
        {
            // public static void ListEntries(PwDatabase pwDb)
            dictionary = null;

            DpiUtil.ConfigureProcess();//needed?

            if (!KeePass.Program.CommonInit())//check if in same dir as KeePass??
            {
               
                KeePass.Program.CommonTerminate();
                return;
            }

            IOConnectionInfo ioc = new IOConnectionInfo();
            ioc.Path = databasefile;
                    ioc.CredSaveMode = IOCredSaveMode.NoSave;
            
                    CompositeKey cmpKey = new CompositeKey();

            cmpKey.AddUserKey(new KcpKeyFile(keyfile));

                    if ((cmpKey == null) || (cmpKey.UserKeyCount == 0)) return;

                    PwDatabase pwDb = new PwDatabase();

            pwDb.Open(ioc, cmpKey, null);


            EntryMod.GetAllEntries(pwDb, out dictionary);


            pwDb.Close();
        }
        public static KeyValuePair<string,string> GetEntry(string entry,string databasefile,string keyfile)
        {
            /*
            Assembly assembly = Assembly.LoadFrom(assemblyPath);
            Type T = assembly.GetType("Company.Project.Classname");
            Company.Project.Classname instance = (Company.Project.Classname)Activator.CreateInstance(T);
            */

            //Read string databasefile,string keyfile from config
            KeyValuePair<string, string> keyval = new KeyValuePair<string, string>("Username", null);

            DpiUtil.ConfigureProcess();//needed?

            if (!KeePass.Program.CommonInit())//check if in same dir as KeePass??
            {
               
                KeePass.Program.CommonTerminate();
                return keyval;
            }

            IOConnectionInfo ioc = new IOConnectionInfo();
            ioc.Path = databasefile;
            ioc.CredSaveMode = IOCredSaveMode.NoSave;
            
            CompositeKey cmpKey = new CompositeKey();

            cmpKey.AddUserKey(new KcpKeyFile(keyfile));

            if ((cmpKey == null) || (cmpKey.UserKeyCount == 0)) return keyval;

            PwDatabase pwDb = new PwDatabase();

            pwDb.Open(ioc, cmpKey, null);

            string password;
            //bool bNeedsSave;
            if(ReportingMod.GetEntryString(pwDb, entry, out password))
                keyval = new KeyValuePair<string, string>("Username", password);
            // if (bNeedsSave) pwDb.Save(null);


            pwDb.Close();
		

            return keyval;
        }
    }
}
