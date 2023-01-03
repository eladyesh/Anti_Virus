def count_up_to(max):
    count = 1
    while count <= max:
        yield count
        count += 1


for number in count_up_to(5):
    print(number)

# Output: 1 2 3 4 5
