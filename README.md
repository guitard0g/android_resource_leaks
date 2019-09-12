** Remembrall **
** Detection of Android resource leaks using static analysis **

How to run (Python 3.5+): 
```
pip install -r requirements.txt
python analyze.py <apk-file.apk>
```

If you get an error installing from pip, you may need to install androguard from source:
```
git clone --recursive https://github.com/androguard/androguard.git
cd androguard
git checkout 5d9e496695860a86ac973bbf3c93e83b50e499c4
pip install .
```
We have to install this specific commit because of a recent issue on the repo: 
https://github.com/androguard/androguard/issues/694

Be sure to source your virtual environment if you are using it to run analyze.py!

You will be prompted for an APK file to analyze. The analysis may take
some time to run its course, as decompilation takes some time.

Two example apks are included, called "app-debug.apk" and "app-debug-bad.apk". 
These are two simple apks that utilize the camera resource, one with proper
resource management and one without.
