/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const collection = app.findCollectionByNameOrId("pbc_1704985774")

  // add field
  collection.fields.addAt(11, new Field({
    "help": "",
    "hidden": false,
    "id": "json3274825913",
    "maxSize": 2000000,
    "name": "pointers",
    "presentable": false,
    "required": false,
    "system": false,
    "type": "json"
  }))

  // add field
  collection.fields.addAt(12, new Field({
    "autogeneratePattern": "",
    "help": "",
    "hidden": false,
    "id": "text3045400989",
    "max": 0,
    "min": 0,
    "name": "introduced_at",
    "pattern": "",
    "presentable": false,
    "primaryKey": false,
    "required": false,
    "system": false,
    "type": "text"
  }))

  // add field
  collection.fields.addAt(13, new Field({
    "autogeneratePattern": "",
    "help": "",
    "hidden": false,
    "id": "text3350553471",
    "max": 0,
    "min": 0,
    "name": "introducing_commit",
    "pattern": "",
    "presentable": false,
    "primaryKey": false,
    "required": false,
    "system": false,
    "type": "text"
  }))

  return app.save(collection)
}, (app) => {
  const collection = app.findCollectionByNameOrId("pbc_1704985774")

  // remove field
  collection.fields.removeById("json3274825913")

  // remove field
  collection.fields.removeById("text3045400989")

  // remove field
  collection.fields.removeById("text3350553471")

  return app.save(collection)
})
