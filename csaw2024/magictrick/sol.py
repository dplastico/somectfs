# Define the reference string
reference_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

# Read the content from output.txt
with open('output.txt', 'r', encoding='utf-8') as file:
    output_content = file.read()

# Create the equivalence dictionary
equivalence_dict = {}
for i in range(min(len(reference_string), len(output_content))):
    reference_char = reference_string[i]
    output_char = output_content[i]
    equivalence_dict[output_char] = reference_char

# Read the content from sample.txt
with open('sample.txt', 'r', encoding='utf-8') as file:
    sample_content = file.read()

# Translate the content from sample.txt using the equivalence dictionary
translated_content = ''.join(equivalence_dict.get(char, '?') for char in sample_content)

# Print the equivalence dictionary
print("Equivalence Dictionary:")
for output_char, reference_char in equivalence_dict.items():
    print(f"'{output_char}' -> '{reference_char}'")

# Print the translated content from sample.txt
print("\nTranslated Content from sample.txt:")
print(translated_content)
