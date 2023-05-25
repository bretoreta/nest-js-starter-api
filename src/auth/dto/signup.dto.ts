import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";

export class SignupDTO {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  firstName: string;

  @IsString()
  @IsOptional()
  middleName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;
}
