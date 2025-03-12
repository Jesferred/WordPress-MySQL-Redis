provider "aws" {
  region = var.region

  default_tags {
    tags = var.common_tags
  }
}

data "aws_ami" "latest_ubuntu" {
  owners      = ["099720109477"]
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

# ------------------------------------------------------------------
# Generate passwords

resource "random_string" "db_username" {
  length  = 8
  upper   = false
  special = false
  numeric = false
}

resource "random_password" "db_password" {
  length           = 16
  override_special = "!#$%&*()-_=+[]{}<>:?"
  special          = true
}


# ------------------------------------------------------------------
# VPC / Subnets / IGW / Route Table

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr
  tags = {
    Name = "main-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "main-igw"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-west-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "public-subnet"
  }
}

resource "aws_subnet" "private_subnet_rds" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "eu-west-1a"
  tags = {
    Name = "private-subnet-rds"
  }
}

resource "aws_subnet" "private_subnet_cache" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "eu-west-1b"
  tags = {
    Name = "private-subnet-cache"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table_association" "public_association" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# ------------------------------------------------------------------
# Security groups

resource "aws_security_group" "server" {
  name   = "SSH-HTTP/S"
  vpc_id = aws_vpc.main.id
  dynamic "ingress" {
    for_each = var.allow_ports_default
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ec2-rds-tf" {
  name   = "EC2-RDS-TF"
  vpc_id = aws_vpc.main.id
  dynamic "egress" {
    for_each = var.allow_ports_ec2_rds
    content {
      from_port   = egress.value
      to_port     = egress.value
      protocol    = "tcp"
      cidr_blocks = [aws_vpc.main.cidr_block]
    }
  }
}

resource "aws_security_group" "rds-ec2-tf" {
  name   = "RDS-EC2-TF"
  vpc_id = aws_vpc.main.id
  dynamic "ingress" {
    for_each = var.allow_ports_ec2_rds
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = [aws_vpc.main.cidr_block]
    }
  }
}

resource "aws_security_group" "ec2-elasticache-tf" {
  name   = "EC2-ELASTICACHE"
  vpc_id = aws_vpc.main.id
  dynamic "ingress" {
    for_each = var.allow_ports_ec2_elasticache
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = [aws_vpc.main.cidr_block]
    }
  }
}

resource "aws_security_group" "elasticache-ec2-tf" {
  name   = "ELASTICACHE-EC2"
  vpc_id = aws_vpc.main.id
  dynamic "egress" {
    for_each = var.allow_ports_ec2_elasticache
    content {
      from_port   = egress.value
      to_port     = egress.value
      protocol    = "tcp"
      cidr_blocks = [aws_vpc.main.cidr_block]
    }
  }
}

resource "aws_security_group" "vpc-security-group-rds" {
  name   = "vpc-security-group-rds"
  vpc_id = aws_vpc.main.id
  dynamic "ingress" {
    for_each = var.allow_ports_ec2_rds
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = [aws_vpc.main.cidr_block]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ------------------------------------------------------------------
# IAM

resource "aws_iam_role" "ec2_ssm_role" {
  name = "ec2-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_attachment" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = aws_iam_role.ec2_ssm_role.arn
  depends_on = [aws_iam_role.ec2_ssm_role]
}

resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm_role.name
}

# ------------------------------------------------------------------
# RDS

resource "aws_db_subnet_group" "rds_subnet" {
  name       = "rds-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_rds.id, aws_subnet.private_subnet_cache.id]
  tags = {
    Name = "rds-subnet-group"
  }
}

resource "aws_db_instance" "wordpress_db" {
  identifier             = "wordpress-db"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = random_string.db_username.result
  password               = random_password.db_password.result
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet.name
  vpc_security_group_ids = [aws_security_group.rds-ec2-tf.id, aws_security_group.vpc-security-group-rds.id]
  skip_final_snapshot    = true
  publicly_accessible    = false
  multi_az               = false
  storage_type           = "gp2"
  deletion_protection    = false
  tags = {
    Name = "wordpress-db"
  }
}

# ------------------------------------------------------------------
# ElastiCache

resource "aws_elasticache_subnet_group" "cache_subnet" {
  name       = "cache-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_cache.id]
  tags = {
    Name = "cache-subnet-group"
  }
}

resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "wordpress-redis"
  engine               = "redis"
  engine_version       = "7.0"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.cache_subnet.name
  security_group_ids   = [aws_security_group.elasticache-ec2-tf.id]
  tags = {
    Name = "wordpress-redis"
  }
}

# ------------------------------------------------------------------
# SSM Parameters to store credentials

resource "aws_ssm_parameter" "mysql-username" {
  name  = "mysql-username"
  type  = "SecureString"
  value = random_string.db_username.result
}

resource "aws_ssm_parameter" "mysql-password" {
  name  = "mysql-password"
  type  = "SecureString"
  value = random_password.db_password.result
}

resource "aws_ssm_parameter" "redis-endpoint" {
  name  = "redis-endpoint"
  type  = "SecureString"
  value = aws_elasticache_cluster.redis.cache_nodes[0].address
}

resource "aws_ssm_parameter" "mysql-endpoint" {
  name  = "mysql-endpoint"
  type  = "SecureString"
  value = aws_db_instance.wordpress_db.address
}

# ------------------------------------------------------------------
# EC2

resource "aws_instance" "wordpress" {
  ami           = data.aws_ami.latest_ubuntu.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public_subnet.id
  vpc_security_group_ids = [
    aws_security_group.server.id,
    aws_security_group.ec2-rds-tf.id,
    aws_security_group.ec2-elasticache-tf.id
  ]
  iam_instance_profile = aws_iam_instance_profile.ec2_ssm_profile.name
  key_name             = "new-key-2025-eu-west-1"
  user_data            = <<-EOF
#!/bin/bash
# editable variables
export WP_ADMIN="admin"
export WP_PASS="passsw0rd"
export WP_EMAIL="test@megatest.com"


export WORDPRESS_DIR="/var/www/html"

# take public ip using IMDSv2
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
export PUBLIC_IP=`curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4`

# main script
apt update
apt install -y apache2 php php-mysql php-redis mysql-client unzip wget curl
cd /tmp
wget https://wordpress.org/latest.tar.gz
tar -xvzf latest.tar.gz

mv wordpress/* $WORDPRESS_DIR
cd $WORDPRESS_DIR
chown -R www-data:www-data $WORDPRESS_DIR
chmod -R 755 $WORDPRESS_DIR
cp $WORDPRESS_DIR/wp-config-sample.php $WORDPRESS_DIR/wp-config.php
rm index.html

# install aws cli to retrieve variables
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
export DB_NAME="wordpress"
export DB_USER=`aws ssm get-parameters --name mysql-username --region eu-west-1 --output text --query Parameters[].Value --with-decryption`
export DB_PASS=`aws ssm get-parameters --name mysql-password --region eu-west-1 --output text --query Parameters[].Value --with-decryption`
export DB_HOST=`aws ssm get-parameters --name mysql-endpoint --region eu-west-1 --output text --query Parameters[].Value --with-decryption`
export REDIS_HOST=`aws ssm get-parameters --name redis-endpoint --region eu-west-1 --output text --query Parameters[].Value --with-decryption`

# configuring wp-config.php
sed -i "s/database_name_here/$DB_NAME/" $WORDPRESS_DIR/wp-config.php
sed -i "s/username_here/$DB_USER/" $WORDPRESS_DIR/wp-config.php
sed -i "s/password_here/$DB_PASS/" $WORDPRESS_DIR/wp-config.php
sed -i "s/localhost/$DB_HOST/" $WORDPRESS_DIR/wp-config.php

echo "define('WP_REDIS_HOST', '$REDIS_HOST');" | sudo tee -a $WORDPRESS_DIR/wp-config.php > /dev/null
echo "define('WP_REDIS_PORT', 6379);" | sudo tee -a $WORDPRESS_DIR/wp-config.php > /dev/null
echo "define('WP_CACHE', true);" | sudo tee -a $WORDPRESS_DIR/wp-config.php > /dev/null
echo "define('WP_REDIS_SCHEME', 'tls');" | sudo tee -a $WORDPRESS_DIR/wp-config.php > /dev/null


# connect & create database
mysql -h "$DB_HOST" -u "$DB_USER" -p "$DB_PASS" -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"
exit

# install wp-cli for automated configuring WordPress
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
mv wp-cli.phar /usr/local/bin/wp
cd $WORDPRESS_DIR

# wp-cli
sudo -u www-data wp core install \
  --url="http://PUBLIC_IP" \
  --title="My WordPress Site" \
  --admin_user="$WP_ADMIN" \
  --admin_password="$WP_PASS" \
  --admin_email="$WP_EMAIL"

# enabling cache
sudo -u www-data wp plugin install redis-cache --activate
sudo -u www-data wp redis enable

# na vsyakiy sluchai
systemctl restart apache2



# TROUBLESHOOTING:
# check installed wp
# curl 127.0.0.1

# check redis
# redis-cli --tls -h $REDIS_HOST ping

# check connection to database
# mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"
  EOF

  tags = {
    Name = "wordpress-ec2"
  }
}



# TODO: разобраться с секьюрити группами
# VPC -> 3 subnets -> route table -> IGW
# IAM role ec2+ssm
# Create RDS in VPC + 2 security groups
# Create Elasticache + 2 security group (Default)
# Import credentials (4) into Parameter Store
# Create EC2 in VPC + 3 security groups + IAM role
# мб чето забыл



















# resource "aws_ssm_parameter" "rds_password" {
#   name        = "/prod/mysql"
#   description = "pass for mysql"
#   type        = "SecureString"
#   value       = random_password.rds_password.result
# }

# output "rds_password" {
#   value     = nonsensitive(data.aws_ssm_parameter.my_rds_password.value)
#   sensitive = true
# }

# data "aws_ssm_parameter" "my_rds_password" {
#   name       = "/prod/mysql"
#   depends_on = [aws_ssm_parameter.rds_password]
# }

# resource "aws_db_instance" "default" {
#   identifier           = "prod-rds"
#   allocated_storage    = 10
#   db_name              = "mydb"
#   engine               = "mysql"
#   engine_version       = "8.0"
#   instance_class       = "db.t3.micro"
#   username             = "admin"
#   password             = data.aws_ssm_parameter.my_rds_password.value
#   parameter_group_name = "default.mysql8.0"
#   skip_final_snapshot  = true
#   apply_immediately    = true
# }
