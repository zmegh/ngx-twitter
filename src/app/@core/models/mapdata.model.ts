export class mapData {
  public code: string;
  public name: string;
  public value: Number;
  public color: string;

  constructor(
   code: string,
   name: string,
   value: Number,
    color: string) {
    this.code = code;
    this.name = name;
    this.value = value;
    this.color = color;
  }
}
