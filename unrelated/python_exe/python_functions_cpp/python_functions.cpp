#include <Python.h>
#include <iostream>

int main(int argc, char *argv[]) {
  Py_Initialize();

  std::cout << argv[0];
  PyObject* module = PyImport_ImportModule(argv[1]);
  if (!module) {
    // An error occurred, handle it here
    return 1;
  }

  PyObject* dict = PyModule_GetDict(module);
  PyObject *key, *value;
  Py_ssize_t pos = 0;
  while (PyDict_Next(dict, &pos, &key, &value)) {
    if (PyFunction_Check(value)) {
      PyObject* func_name = PyObject_Str(key);
      PyObject* arg_names = reinterpret_cast<PyCodeObject*>(PyFunction_GetCode(value))->co_varnames;
      int num_args = reinterpret_cast<PyCodeObject*>(PyFunction_GetCode(value))->co_argcount;
      std::cout << "Function: " << PyUnicode_AsUTF8(func_name) << std::endl;
      std::cout << "  Number of arguments: " << num_args << std::endl;
      std::cout << "  Argument names: ";
      for (int i = 0; i < num_args; ++i) {
        PyObject* arg_name = PyTuple_GetItem(arg_names, i);
        std::cout << PyUnicode_AsUTF8(arg_name) << " ";
      }
      std::cout << std::endl;
    }
  }

  Py_DECREF(module);
  Py_DECREF(dict);
  Py_Finalize();
  return 0;
}
