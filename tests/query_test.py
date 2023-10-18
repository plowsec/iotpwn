from tree_sitter import Language, Parser

Language.build_library(
  '../build/my-languages.so',
  ['../vendor/tree-sitter-c']
)

C_LANGUAGE = Language('../build/my-languages.so', 'c')
parser = Parser()
parser.set_language(C_LANGUAGE)


# Example C code
code = """
void my_function(int limit) {
    char buffer[100];
    for (int i = 0; i < limit; i++) {
        buffer[i] = 'a';
    }
}
"""

# Create query
query_string = """
(function_definition
  (parameter_list
    (parameter_declaration
      (primitive_type) @type
      (identifier) @argname))
  (compound_statement
    (declaration
      (identifier) @buffer)
    (for_statement
      (expression_statement
        (identifier) @loopvar)
      (expression_statement
        (identifier) @loopvar)
      (compound_statement
        (expression_statement
          (subscript_expression
            (identifier) @buffer)))))
)
"""


if __name__ == "__main__":

    # Compile the query
    query = C_LANGUAGE.query(query_string)

    # Parse the code
    tree = parser.parse(bytes(code, "utf8"))

    # Run the query
    captures = query.captures(tree.root_node)
