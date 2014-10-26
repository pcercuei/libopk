using System;
using System.Runtime.InteropServices;

namespace opk
{
	public class Opk
	{
		private IntPtr opk;

		[DllImport("libopk.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern IntPtr opk_open(
			[In()][MarshalAs(UnmanagedType.LPStr)] string filename);

		[DllImport("libopk.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern void opk_close(IntPtr opk);

		[DllImport("libopk.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern int opk_open_metadata(IntPtr opk, ref IntPtr filename);

		[DllImport("libopk.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern int opk_read_pair(IntPtr opk,
					ref IntPtr key, ref ulong key_len,
					ref IntPtr val, ref ulong val_len);

		public Opk(string filename)
		{
			this.opk = opk_open(filename);
		}

		~Opk()
		{
			opk_close(this.opk);
		}

		public string open_metadata()
		{
			IntPtr ptr = (IntPtr) 0;

			int ret = opk_open_metadata(this.opk, ref ptr);
			if (ret < 0)
				throw new Exception("Unable to open metadata: err=" + ret);
			if (ret == 0)
				return null;

			return Marshal.PtrToStringAnsi(ptr);
		}

		public bool read_pair(out string key, out string value)
		{
			IntPtr kptr = (IntPtr) 0, vptr = (IntPtr) 0;
			ulong klen = 0, vlen = 0;

			int ret = opk_read_pair(this.opk, ref kptr, ref klen, ref vptr, ref vlen);
			if (ret < 0)
				throw new Exception("Unable to read key/value pair: err=" + ret);
			if (ret == 0) {
				key = null;
				value = null;
				return false;
			}

			value = Marshal.PtrToStringAnsi(vptr, (int) vlen);
			key = Marshal.PtrToStringAnsi(kptr, (int) klen);
			return true;
		}
	}
}
