from spectrum import db
from spectrum.database import Category

db.create_all()
catlist = ['New Arrival', 'Most Popular', 'Limited Time', 'Top', 'Bottom', 'Socks', 'Shoes', 'Equipments', 'Accessories', 'Others']
for cat in catlist:
    cate = Category(name=cat)
    db.session.add(cate)
    print(f'{cate} category has been added')

db.session.commit()