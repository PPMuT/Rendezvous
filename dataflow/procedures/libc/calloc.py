#
# import dataflow
#
# class calloc(dataflow.SimProcedure):
#     def run(self, c,size):
#         r = 1
#         if self.flow_dir == 'B' and self.purpose == 0:
#             r = self.update_with_heap(size)
#         return r
#
#     def infer_type(self, c,nptr):
#         self.label_variable_type(nptr, 'ptr')
#         self.label_variable_type(c, 'ptr')
#         self.label_return_type('ptr')
