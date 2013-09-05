/*!
 * \mainpage CryptImpHook.c
 *
 * \version 1.0
 * \date 2011
 * \author Jesus Rivero (Neurogeek) <neurogeekster@gmail.com>, <neurogeek@gentoo.org>
 *
 * LGPL-2.1. The license and distribution terms for this file may be
 * found in the file LICENSE in this distribution or at
 *
 * \section Main
 *  CryptImpHook is a CPython Import Hook (see PEP-302) that allows encrypted Python modules
 *  to be used in a transparent manner in any Python application. The encrypted
 *  modules have a .pyx extension.
 *
 *  This code is just a proof-of-concept and implements the XOR encryption
 *  with a given key. If you would like to change the encryption cipher or mechanism, you could
 *  implement yours by re_writing the cih_read_module_code function.
 *
 */
#include <Python.h>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "Cipher.h"
#include "CryptImpHook.h"

///! Some constants used for the new imported module.
const char *FILE_ITEM = "__file__";
const char *LOADER_ITEM = "__loader__";
const char *DICT_ITEM = "__dict__";

///! The Python type for the Object
static PyTypeObject CryptImpHook_Type;

///! The new suffix for encrypted Python modules.
///! Just for convinience.
static const char *IMPHOOK_SUFFIX = ".pye";

/*! \struct CryptImpHook
 *  \brief PyObject initial segment, plus a new attribute to hold
 *  the name of the file of the module to be imported.
 */
typedef struct {
  PyObject_HEAD
  PyObject *mod_file;
} CryptImpHook;

///! Constructor
static PyObject *
CryptImpHook_NEW()
{
	CryptImpHook *hook;

    hook = PyObject_NEW(CryptImpHook, &CryptImpHook_Type);
    hook->mod_file = PyString_FromString("");
    Py_INCREF(hook->mod_file);

    return (PyObject *)hook;
}

///! Destructor
static void
CryptImpHook_dealloc(self)
PyObject *self;
{
	CryptImpHook *hook = (CryptImpHook *)self;
	Py_DECREF(hook->mod_file);
	Py_DECREF(self);
}

/*
 * Methods
 * We need to implement and expose two methods for the Hook:
 * - find_module: which is called from import. It shall return an object if it should be used for loading.
 * - load_module: which is called is find_module returns a Not None object. This returns the module.
 */

/*!
 * \brief Finds out if a file with an IMPHOOK_SUFFIX exists.
 * \param fullname is the name (no suffix/extension) of the file to search for
 * \return the complete path of the file, or NULL if no matching file exists.
 */
char *
cih_get_path(const char *fullname)
{
	int res;
	ssize_t ssize;
	struct stat buf;
	char *filename;

	filename = (char *)malloc(sizeof(char) * 512);
	filename = (char *)memset(filename, 0, sizeof(char) * 512);

	ssize = strlen(fullname);
	strncat(filename, fullname, ssize);
	strncat(filename, IMPHOOK_SUFFIX, strlen(IMPHOOK_SUFFIX));

	//We should have our filename as fullname.pyx.
	//If we find it, then we should return self.
	res = stat(filename, &buf);

	if(res == 0){
		return filename;
	}

	return NULL;
}

/*! \brief Reads and decrypts a file from a path.
 *  \param filename The fullname of a file, path included.
 *  \return The decoded string, or NULL if an Error ocurred.
 */
char *
cih_read_module_code(char *filename)
//CryptImpHook_cih_read_module_code(PyObject *filename)
{
	FILE *fp;
	ssize_t total;
	struct stat buf;
	int err, dec_len;
    int idx = 0;
    int ktal = strlen(qta);
    int btodec;
    char *temp, *tmp_name;
	char *module_code, *dec_module_code;

    temp = (char*)malloc(sizeof(char));
    tmp_name = (char *)malloc(sizeof(char) * (strlen(filename) + 4));

    sprintf(tmp_name, "%s%s", filename, IMPHOOK_SUFFIX);
    char *chr_filename = tmp_name;

	/* Instead of doing the stat twice, we could store a PyTuple instead of a PyString in hook->mod_file
	 * At least we now the stat is good
	 */

	if ((err = stat(chr_filename, &buf)) != 0) {
        printf("Error ocurred %d\n", errno);
        return NULL;
    }

	dec_module_code = (char *)malloc(sizeof(char) * buf.st_size); //We grab the file size in bytes
	memset(dec_module_code, 0, sizeof(char) * buf.st_size);

	if(module_code == NULL){
		return NULL;
	}

	fp = fopen(chr_filename, "r");
    while( (btodec = fgetc(fp)) != EOF )
    {
        sprintf(temp, "%c", XOR(btodec, qta[idx % ktal]));
        strncat(dec_module_code, temp, sizeof(char));
        idx++;
    }
	err = ferror(fp);

	if((err))
	{
		return NULL;
	}
	fclose(fp);

    free(temp);
    free(tmp_name);
	return dec_module_code;
}

/*! \brief This is the implementation of the Object's find_module.
 *
 * According to Python's PEP 302, Import Hooks should expose at least two functions. This
 * is one of them.
 *
 * \param self Pointer to the CryptImpHook Object.
 * \param args PyObject representing *args list. This one can have one or two elements. The first
 * one is the module name, the second, a path.
 * \return self (a PyObject) is the module exists, NULL if it does not exist.
 */
PyObject *
CryptImpHook_find_module(self, args)
PyObject *self, *args;
{
	int err;
	char *filename, *fullname, *path;
	CryptImpHook *hook = (CryptImpHook *)self;

	err = PyArg_ParseTuple(args, "s|z", &fullname, &path);

	if(err == 0)
	{
		PyObject_Print(PyErr_Occurred(), stdout, Py_PRINT_RAW);
		PySys_WriteStdout("\n");
		PyErr_Print();
		PySys_WriteStdout("\n");
	}

	filename = cih_get_path(fullname);

	if(filename != NULL)
	{
		hook->mod_file = PyString_FromString(filename);
		free(filename);

		return self;
	}else{
		free(filename);
		return Py_None;
	}
}

/*! \brief Function to load the Python module.
 *
 * This is the second function that an ImportHook has to expose. This function
 * reads the module, decrypts it, creates a new Python module, configures it and returns it.
 *
 * \param self Pointer to the CryptImpHook Object.
 * \param args PyObject representing *args list. This onw has one element that represents the fullname (with path)
 * of the file containing the searched module.
 * \returns A new Python module all set, or NULL if an error ocurred.
 * \todo Clean up and look for failures.
 */
PyObject *
CryptImpHook_load_module(self, args)
PyObject *self, *args;
{
	int err;
	char *module_code, *fullname;
	PyObject *new_mod, *sys_module_dict, *new_module_dict, *res;

	CryptImpHook *hook = (CryptImpHook *)self;

	PyArg_ParseTuple(args, "s", &fullname);
	new_mod = PyModule_New(fullname);
	Py_INCREF(new_mod);

	err = PyModule_AddObject(new_mod, FILE_ITEM, hook->mod_file);
	if(err != 0)
	{
		PyObject_Print(PyErr_Occurred(), stdout, Py_PRINT_RAW);
		PySys_WriteStdout("\n");
		PyErr_Print();
		PySys_WriteStdout("\n");
	}
	err = PyModule_AddObject(new_mod, LOADER_ITEM, self);

	if(err != 0)
	{
		PyObject_Print(PyErr_Occurred(), stdout, Py_PRINT_RAW);
		PySys_WriteStdout("\n");
		PyErr_Print();
		PySys_WriteStdout("\n");
	}

	sys_module_dict = PyImport_GetModuleDict();

	if(sys_module_dict != NULL)
	{
		PyDict_SetItemString(sys_module_dict, fullname, new_mod);
        PyModule_AddObject(new_mod, "__builtins__", PyDict_GetItemString(sys_module_dict, "__builtin__"));
	}

	module_code = cih_read_module_code(fullname);
	//Next, we grab the reference to the new module's __dict__

    if(module_code == NULL) {
        //We couldnt load the module. Raise ImportError
        return PyExc_ImportError;
    }
	new_module_dict = PyModule_GetDict(new_mod);

	/*
	 * This is really important. the second arg should be Py_file_input because we need
	 * the interpreter to believe is a file, and accept multiple statements in multiple lines.
	 * Else, the plug-in should throw a SegFault.
	 */

	/* Now eval in context with new_mod.__dict__ in both globals and locals;
	 * The following (I believe) would be the translation in C of the
	 * exec CODE in mod.__dict__
	 */
	res = PyRun_String(module_code, Py_file_input, new_module_dict, new_module_dict);
	return new_mod;
}

///! MethodTable for CryptImpHook
static PyMethodDef CryptImpHook_methods[] = {
  {"find_module", CryptImpHook_find_module, METH_VARARGS},
  {"load_module", CryptImpHook_load_module, METH_VARARGS},
  {NULL, NULL},
};

///! We provide a getattr method
static PyObject *
CryptImpHook_GetAttr(self, attrname)
PyObject *self;
char *attrname;
{
	return Py_FindMethod(CryptImpHook_methods, self, attrname);
}

///! Type definition. Continuation of the static(forward) declaration
static PyTypeObject CryptImpHook_Type = {
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "CryptImpHook",
  sizeof(CryptImpHook),
  0,
  (destructor)CryptImpHook_dealloc,
  0,
  (getattrfunc)CryptImpHook_GetAttr,
  0,
  0,
  0,
  0,
  /* the rest are NULLs */
};

// Now, we take care of the module.
///! CPython constructor
static PyObject *
CryptImpHook_new(self, args)
PyObject *self, *args;
{
	PyObject *result = NULL;
	result = CryptImpHook_NEW();
    return result;
}

///! CPython Module functions
static PyMethodDef methods[] = {
  {"CryptImpHook", CryptImpHook_new, METH_VARARGS},
  {NULL, NULL},
};

///! Module init function
void initCryptImpHook()
{
	PyObject *m;
    m = Py_InitModule("CryptImpHook", methods);
}


