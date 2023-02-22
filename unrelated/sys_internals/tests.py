from dataclasses import dataclass, field


@dataclass
class Person:
    name: str = field(init=False, repr=True, compare=True)
    age: int
    email: str

    def __post_init__(self):
        object.__setattr__(self, "name", "Constant Name")


# creating a new instance of the Person class
person1 = Person(25, "alice@example.com")

# trying to change the value of the 'name' attribute will raise an AttributeError
try:
    person1.name = "New Name"
except AttributeError as e:
    print(f"Error: {e}")

# the value of the 'name' attribute is constant and set to "Constant Name"
print(person1.name)
