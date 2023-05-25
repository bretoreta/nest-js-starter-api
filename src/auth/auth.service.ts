import { Injectable, ForbiddenException } from "@nestjs/common";
import { DatabaseService } from "src/database/database.service";
import { SigninDTO, SignupDTO } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
    constructor(private databaseService: DatabaseService, private jwt: JwtService, private config: ConfigService) {}
    
    async signup(dto: SignupDTO) {
        try {
            // Generate hashed password
            const hash = await argon.hash(dto.password)
            const user = await this.databaseService.user.create({
                data: {
                    email: dto.email,
                    password: hash,
                    firstName: dto.firstName,
                    middleName: dto.middleName,
                    lastName: dto.lastName,
                }
            })

            return this.signToken(user.id, user.email);
            
        } catch (error) {
            if(error instanceof PrismaClientKnownRequestError) {
                if(error.code === 'P2002') {
                    throw new ForbiddenException('Credentials have already been taken');
                }
            }
            throw error;
        }
    }

    async signin(dto: SigninDTO) {
        const user = await this.databaseService.user.findUnique({
            where: {
                email: dto.email
            },
        });;
        if(!user) throw new ForbiddenException('The email entered does not exist in our records');

        const pwdMatches = await argon.verify(user.password, dto.password);
        if(!pwdMatches) throw new ForbiddenException('The password entered is incorrect');

        return this.signToken(user.id, user.email);
    }

    async signToken(userId: number, email: string) : Promise<{access_token : string}> {
        const payload = {
            sub: userId,
            email,
        }

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: this.config.get('JWT_SECRET'),
        });

        return {
            access_token : token,
        }
    }
}
